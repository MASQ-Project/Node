// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod client_request_payload_factory;
pub mod http_protocol_pack;
pub mod protocol_pack;
pub mod server_impersonator_http;
pub mod server_impersonator_tls;
pub mod tls_protocol_pack;

use crate::proxy_server::client_request_payload_factory::{
    ClientRequestPayloadFactory, ClientRequestPayloadFactoryReal,
};
use crate::proxy_server::http_protocol_pack::HttpProtocolPack;
use crate::proxy_server::protocol_pack::{from_ibcd, from_protocol, ProtocolPack};
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
use crate::sub_lib::neighborhood::{ExpectedService, UpdateNodeRecordMetadataMessage};
use crate::sub_lib::neighborhood::{ExpectedServices, RatePack};
use crate::sub_lib::neighborhood::{NRMetadataChange, RouteQueryMessage};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::proxy_client::{ClientResponsePayload_0v1, DnsResolveFailure_0v1};
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::proxy_server::StreamKeyPurge;
use crate::sub_lib::proxy_server::{
    AddRouteResultMessage, ClientRequestPayload_0v1, ProxyProtocol,
};
use crate::sub_lib::route::Route;
use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::utils::{handle_ui_crash_request, MessageScheduler, NODE_MAILBOX_CAPACITY};
use crate::sub_lib::wallet::Wallet;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use actix::{Actor, MailboxError};
use actix::{Addr, AsyncContext};
use masq_lib::constants::TLS_PORT;
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::NodeFromUiMessage;
use masq_lib::utils::MutabilityConflictHelper;
use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use tokio::prelude::Future;
use crate::sub_lib::host::Host;

pub const CRASH_KEY: &str = "PROXYSERVER";
pub const RETURN_ROUTE_TTL_FIRST_CHANCE: Duration = Duration::from_secs(120);
pub const RETURN_ROUTE_TTL_STRAGGLERS: Duration = Duration::from_secs(5);
pub const STREAM_KEY_PURGE_DELAY: Duration = Duration::from_secs(30);
pub const DNS_FAILURE_RETRIES: usize = 3;

struct ProxyServerOutSubs {
    dispatcher: Recipient<TransmitDataMsg>,
    hopper: Recipient<IncipientCoresPackage>,
    accountant: Recipient<ReportServicesConsumedMessage>,
    route_source: Recipient<RouteQueryMessage>,
    update_node_record_metadata: Recipient<UpdateNodeRecordMetadataMessage>,
    stream_shutdown_sub: Recipient<StreamShutdownMsg>,
    route_result_sub: Recipient<AddRouteResultMessage>,
    schedule_stream_key_purge: Recipient<MessageScheduler<StreamKeyPurge>>,
}

#[derive(Clone, Debug)]
struct StreamInfo {
    tunneled_host_opt: Option<String>,
    dns_failure_retry_opt: Option<DNSFailureRetry>,
    route_opt: Option<RouteQueryResponse>,
    protocol_opt: Option<ProxyProtocol>,
    time_to_live_opt: Option<SystemTime>,
}

pub struct ProxyServer {
    subs: Option<ProxyServerOutSubs>,
    client_request_payload_factory: Box<dyn ClientRequestPayloadFactory>,
    stream_key_factory: Box<dyn StreamKeyFactory>,
    keys_and_addrs: BidiHashMap<StreamKey, SocketAddr>,
    stream_info: HashMap<StreamKey, StreamInfo>,
    is_decentralized: bool,
    consuming_wallet_balance: Option<i64>,
    main_cryptde: &'static dyn CryptDE,
    alias_cryptde: &'static dyn CryptDE,
    crashable: bool,
    logger: Logger,
    // // Holds return-route information for requests that have not yet seen any responses
    // route_ids_to_return_routes_first_chance: TtlHashMap<u32, AddReturnRouteMessage>,
    // // Holds return-route information for requests that have seen at least one response and may
    // // see more in the future. The near future, because this TTL is much shorter.
    // route_ids_to_return_routes_stragglers: TtlHashMap<u32, AddReturnRouteMessage>,
    browser_proxy_sequence_offset: bool,
    inbound_client_data_helper_opt: Option<Box<dyn IBCDHelper>>,
    stream_key_purge_delay: Duration,
    is_running_in_integration_test: bool,
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
            stream_shutdown_sub: msg.peer_actors.proxy_server.stream_shutdown_sub,
            route_result_sub: msg.peer_actors.proxy_server.route_result_sub,
            schedule_stream_key_purge: msg.peer_actors.proxy_server.schedule_stream_key_purge,
        };
        self.subs = Some(subs);
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

impl Handler<AddRouteResultMessage> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: AddRouteResultMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_add_route_result_message(msg)
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

impl Handler<StreamKeyPurge> for ProxyServer {
    type Result = ();

    fn handle(&mut self, msg: StreamKeyPurge, _ctx: &mut Self::Context) -> Self::Result {
        self.purge_stream_key(&msg.stream_key, "scheduled message");
    }
}

impl<M: actix::Message + 'static> Handler<MessageScheduler<M>> for ProxyServer
where
    ProxyServer: Handler<M>,
{
    type Result = ();

    fn handle(&mut self, msg: MessageScheduler<M>, ctx: &mut Self::Context) -> Self::Result {
        ctx.notify_later(msg.scheduled_msg, msg.delay);
    }
}

impl ProxyServer {
    pub fn new(
        main_cryptde: &'static dyn CryptDE,
        alias_cryptde: &'static dyn CryptDE,
        is_decentralized: bool,
        consuming_wallet_balance: Option<i64>,
        crashable: bool,
        is_running_in_integration_test: bool,
    ) -> ProxyServer {
        let ps_logger = Logger::new("ProxyServer");
        ProxyServer {
            subs: None,
            client_request_payload_factory: Box::new(ClientRequestPayloadFactoryReal::new()),
            stream_key_factory: Box::new(StreamKeyFactoryReal {}),
            keys_and_addrs: BidiHashMap::new(),
            stream_info: HashMap::new(),
            is_decentralized,
            consuming_wallet_balance,
            main_cryptde,
            alias_cryptde,
            crashable,
            logger: ps_logger,
            browser_proxy_sequence_offset: false,
            inbound_client_data_helper_opt: Some(Box::new(IBCDHelperReal::new())),
            stream_key_purge_delay: STREAM_KEY_PURGE_DELAY,
            is_running_in_integration_test,
        }
    }

    pub fn make_subs_from(addr: &Addr<ProxyServer>) -> ProxyServerSubs {
        ProxyServerSubs {
            bind: recipient!(addr, BindMessage),
            from_dispatcher: recipient!(addr, InboundClientData),
            from_hopper: recipient!(addr, ExpiredCoresPackage<ClientResponsePayload_0v1>),
            dns_failure_from_hopper: recipient!(addr, ExpiredCoresPackage<DnsResolveFailure_0v1>),
            stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
            node_from_ui: recipient!(addr, NodeFromUiMessage),
            route_result_sub: recipient!(addr, AddRouteResultMessage),
            schedule_stream_key_purge: recipient!(addr, MessageScheduler<StreamKeyPurge>),
        }
    }

    fn stream_info(&self, stream_key: &StreamKey, logger: &Logger) -> Option<&StreamInfo> {
        match self.stream_info.get(stream_key) {
            None => {
                error!(logger, "Stream key {} not found in stream_info", stream_key);
                None
            }
            Some(info) => Some(info),
        }
    }

    fn stream_info_mut(&mut self, stream_key: &StreamKey) -> Option<&mut StreamInfo> {
        match self.stream_info.get_mut(stream_key) {
            None => {
                error!(
                    self.logger,
                    "Stream key {} not found in stream_info", stream_key
                );
                None
            }
            Some(info) => Some(info),
        }
    }

    fn remove_dns_failure_retry(
        stream_info: &mut StreamInfo,
        stream_key: &StreamKey,
    ) -> Result<DNSFailureRetry, String> {
        match stream_info.dns_failure_retry_opt.take() {
            None => Err(format!(
                "No DNSFailureRetry entry found for the stream_key: {:?}",
                stream_key
            )),
            Some(retry) => Ok(retry),
        }
    }

    fn retry_dns_resolution(&mut self, retry: &DNSFailureRetry, client_addr: SocketAddr) {
        let args = TransmitToHopperArgs::new(
            self,
            retry.unsuccessful_request.clone(),
            client_addr,
            SystemTime::now(),
            false,
        );
        let route_source = self.out_subs("Neighborhood").route_source.clone();
        let proxy_server_sub = self.out_subs("ProxyServer").route_result_sub.clone();
        let inbound_client_data_helper = self
            .inbound_client_data_helper_opt
            .as_ref()
            .expect("IBCDHelper uninitialized");

        inbound_client_data_helper.request_route_and_transmit(args, route_source, proxy_server_sub);
    }

    fn retire_stream_key(&mut self, stream_key: &StreamKey) {
        self.purge_stream_key(stream_key, "DNS resolution failure");
    }

    fn send_dns_failure_response_to_the_browser(
        &self,
        client_addr: SocketAddr,
        proxy_protocol: ProxyProtocol,
        hostname: String,
    ) {
        self.subs
            .as_ref()
            .expect("Dispatcher unbound in ProxyServer")
            .dispatcher
            .try_send(TransmitDataMsg {
                endpoint: Endpoint::Socket(client_addr),
                last_data: true,
                sequence_number: Some(0), // DNS resolution errors always happen on the first request
                data: from_protocol(proxy_protocol)
                    .server_impersonator()
                    .dns_resolution_failure_response(hostname),
            })
            .expect("Dispatcher is dead");
    }

    fn get_response_services(
        route_query_response: &RouteQueryResponse,
    ) -> Option<&[ExpectedService]> {
        match &route_query_response.expected_services {
            ExpectedServices::RoundTrip(_, back) => Some(back),
            _ => None,
        }
    }

    fn find_exit_node_key(response_services: &[ExpectedService]) -> Option<PublicKey> {
        match response_services.first() {
            Some(ExpectedService::Exit(pk, _, _)) => Some(pk.clone()),
            _ => None,
        }
    }

    fn handle_add_route_result_message(&mut self, msg: AddRouteResultMessage) {
        type DelayedLogArgs = Box<dyn FnOnce(&Logger, String, StreamKey, usize, String)>;
        #[allow(unused_assignments)]
        let mut delayed_log: DelayedLogArgs = Box::new(|_, _, _, _, _| {});
        let (target_hostname, stream_key, retries_left, message) = {
            let mut stream_info = self.stream_info_mut(&msg.stream_key).unwrap_or_else(|| {
                panic!(
                    "AddRouteResultMessage Handler: stream key: {} not found",
                    msg.stream_key
                )
            });
            let dns_failure_retry = stream_info
                .dns_failure_retry_opt
                .as_ref()
                .unwrap_or_else(||
                    panic!("AddRouteResultMessage Handler: dns_failure_retry_opt is None for stream key {}", msg.stream_key)
                );
            let mut message = String::new();
            match msg.result {
                Ok(route_query_response) => {
                    delayed_log = Box::new(
                        move |logger: &Logger,
                              target_hostname: String,
                              stream_key: StreamKey,
                              retries_left: usize,
                              _: String| {
                            debug!(
                            logger,
                            "Found a new route for hostname: {:?} - stream key: {}  retries left: {}",
                            target_hostname,
                            stream_key,
                            retries_left
                        );
                        },
                    );
                    stream_info.route_opt = Some(route_query_response);
                }
                Err(e) => {
                    message = e;
                    delayed_log = Box::new(
                        move |logger: &Logger,
                              target_hostname: String,
                              stream_key: StreamKey,
                              retries_left: usize,
                              message: String| {
                            warning!(
                            logger,
                            "No route found for hostname: {:?} - stream key {} - retries left: {} - AddRouteResultMessage Error: {}",
                            target_hostname,
                            stream_key,
                            retries_left,
                            message
                        );
                        },
                    );
                }
            }
            (
                dns_failure_retry
                    .unsuccessful_request
                    .target_hostname
                    .clone(),
                msg.stream_key,
                dns_failure_retry.retries_left,
                message,
            )
        };
        delayed_log(
            &self.logger,
            target_hostname,
            stream_key,
            retries_left,
            message,
        );
    }

    fn handle_dns_resolve_failure(&mut self, msg: &ExpiredCoresPackage<DnsResolveFailure_0v1>) {
        let response = &msg.payload;

        // The idea here is that the Borrow Checker will not allow us to modify the StreamInfo in
        // ProxyServer's map while we're looking at one of its values. So we're making a mutable
        // copy of the StreamInfo, modifying that as necessary, and then overwriting the original
        // map element with the modified copy at the end of the function. However, under certain
        // circumstances we want to _retire_ the stream key; so we have a restore_stream_info
        // flag that starts out true and is set to false if we retire the stream key. It's an
        // ugly hack. Thanks, Borrow Checker!
        let mut stream_info = match self.stream_info(&response.stream_key, &self.logger) {
            Some(info) => (*info).clone(),
            None => {
                error!(
                    self.logger,
                    "Discarding DnsResolveFailure message from an unrecognized stream key {:?}",
                    &response.stream_key
                );
                return;
            }
        };
        let mut restore_stream_info = true;

        let route_query_response = match &stream_info.route_opt {
            Some(route_query_response) => route_query_response,
            None => {
                error!(
                    self.logger,
                    "Stream info for stream key {} has no route info", &response.stream_key
                );
                return;
            }
        };
        let response_services = match Self::get_response_services(route_query_response) {
            Some(response_services) => response_services,
            None => {
                error!(
                    self.logger,
                    "Stream info for stream key {} has no response services in its route info",
                    &response.stream_key
                );
                return;
            }
        };
        let exit_public_key = if !self.is_decentralized {
            self.main_cryptde.public_key().clone()
        } else {
            match Self::find_exit_node_key(response_services) {
                Some(exit_public_key) => exit_public_key,
                None => {
                    error!(
                        self.logger,
                        "Stream info for stream key {} has no exit node in its response services",
                        &response.stream_key
                    );
                    return;
                }
            }
        };
        let response = &msg.payload;

        match self.keys_and_addrs.a_to_b(&response.stream_key) {
            Some(client_addr) => {
                self.subs
                    .as_ref()
                    .expect("Neighborhood unbound in ProxyServer")
                    .update_node_record_metadata
                    .try_send(UpdateNodeRecordMetadataMessage {
                        public_key: exit_public_key,
                        metadata_change: NRMetadataChange::AddUnreachableHost {
                            hostname: route_query_response.host.name.clone(),
                        },
                    })
                    .expect("Neighborhood is dead");
                self.report_response_services_consumed(response_services, 0, msg.payload_len);
                if let Some(retry_ref) = &mut stream_info.dns_failure_retry_opt {
                    debug!(
                        self.logger,
                        "Handling DNS failure for hostname {:?} - stream key: {}  retries left: {}",
                        retry_ref.unsuccessful_request.target_hostname,
                        &response.stream_key,
                        retry_ref.retries_left
                    );
                    if retry_ref.retries_left > 0 {
                        self.retry_dns_resolution(retry_ref, client_addr);
                        retry_ref.retries_left -= 1;
                    } else {
                        restore_stream_info = false;
                        self.retire_stream_key(&response.stream_key);
                        let protocol = stream_info.protocol_opt.expect(
                            "StreamInfo should always have a protocol_opt set by the time we get a DNS failure"
                        );
                        self.send_dns_failure_response_to_the_browser(
                            client_addr,
                            protocol,
                            route_query_response.host.name.clone(),
                        );
                    }
                } else {
                    error!(
                        self.logger,
                        "While handling ExpiredCoresPackage: No DNSFailureRetry entry found for the stream_key: {:?}",
                        &response.stream_key
                    );
                    return;
                }
            }
            None => {
                error!(self.logger,
                    "Discarding DnsResolveFailure message for {} from an unrecognized stream key {:?}",
                    route_query_response.host.name,
                    &response.stream_key
                )
            }
        }
        if restore_stream_info {
            self.stream_info.insert(response.stream_key, stream_info);
        }
    }

    fn schedule_stream_key_purge(&mut self, stream_key: StreamKey) {
        let stream_key_purge_delay = self.stream_key_purge_delay;
        let mut delayed_log: Box<dyn FnOnce(&Logger)> = Box::new(|_: &Logger| {});
        if let Some(stream_info) = self.stream_info_mut(&stream_key) {
            let host_info = match &stream_info.tunneled_host_opt {
                None => String::from(""),
                Some(hostname) => format!(", which was tunneling to the host {:?}", hostname),
            };
            delayed_log = Box::new(move |logger: &Logger| {
                debug!(
                    logger,
                    "Client closed stream referenced by stream key {:?}{}. It will be purged after {:?}.",
                    &stream_key,
                    host_info,
                    stream_key_purge_delay
                );
            });
            stream_info.time_to_live_opt = Some(SystemTime::now());
            self.subs
                .as_ref()
                .expect("ProxyServer Subs Unbound")
                .schedule_stream_key_purge
                .try_send(MessageScheduler {
                    scheduled_msg: StreamKeyPurge { stream_key },
                    delay: self.stream_key_purge_delay,
                })
                .expect("ProxyServer is dead");
        }
        delayed_log(&self.logger);
    }

    fn log_straggling_packet(
        &self,
        stream_key: &StreamKey,
        packet_len: usize,
        old_timestamp: &SystemTime,
    ) {
        let duration_since = SystemTime::now()
            .duration_since(*old_timestamp)
            .expect("time calculation error");
        debug!(
            self.logger,
            "Straggling packet of length {} received for a stream key {:?} after a delay of {:?}",
            packet_len,
            stream_key,
            duration_since
        );
    }

    fn handle_client_response_payload(
        &mut self,
        msg: ExpiredCoresPackage<ClientResponsePayload_0v1>,
    ) {
        // TODO: Maybe comment this back in. The issue is apparently that the second hop is the
        // return route information, which doesn't to_string() very well anymore.
        // debug!(
        //     self.logger,
        //     "ExpiredCoresPackage remaining_route: {}",
        //     msg.remaining_route
        //         .to_string(vec![self.main_cryptde, self.main_cryptde])
        // );
        let payload_data_len = msg.payload_len;
        let response = msg.payload;
        debug!(
            self.logger,
            "Relaying ClientResponsePayload (stream key {}, sequence {}, length {}) from Hopper to Dispatcher for client",
            response.stream_key, response.sequenced_packet.sequence_number, response.sequenced_packet.data.len()
        );
        let expected_services = match self.get_expected_return_services(&response.stream_key) {
            Some(expected_services) => expected_services,
            None => return,
        };
        self.report_response_services_consumed(
            &expected_services,
            response.sequenced_packet.data.len(),
            payload_data_len,
        );
        let stream_key = response.stream_key;
        let old_timestamp_opt = match self.stream_info_mut(&stream_key) {
            Some(info) => {
                let time_to_live_opt = info.time_to_live_opt;
                // This call to remove_dns_failure_retry is here only because it needs access to
                // a mutable StreamInfo, and we have one handy here. It has nothing to do with
                // timestamps.
                if let Err(e) = ProxyServer::remove_dns_failure_retry(info, &stream_key) {
                    trace!(
                        self.logger,
                        "No DNS retry entry found for stream key {} during a successful attempt: {}",
                        &stream_key, e
                    );
                }
                time_to_live_opt
            }
            None => None,
        };
        if let Some(old_timestamp) = old_timestamp_opt {
            self.log_straggling_packet(&stream_key, payload_data_len, &old_timestamp)
            // TODO: Make sure we actually do something (other than logging) about stragglers.
        } else {
            match self.keys_and_addrs.a_to_b(&stream_key) {
                Some(socket_addr) => {
                    let last_data = response.sequenced_packet.last_data;
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
                        self.purge_stream_key(&stream_key, "last data received from the exit node");
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
    }

    fn tls_connect(&mut self, msg: &InboundClientData) {
        let http_data = HttpProtocolPack {}.find_host(&msg.data.clone().into());
        match http_data {
            Some(ref host) if host.port == TLS_PORT => {
                let stream_key = self.find_or_generate_stream_key(msg);
                match self.stream_info_mut(&stream_key) {
                    None => return,
                    Some(stream_info) => stream_info.tunneled_host_opt = Some(host.name.clone()),
                }
                self.subs
                    .as_ref()
                    .expect("Dispatcher unbound in ProxyServer")
                    .dispatcher
                    .try_send(TransmitDataMsg {
                        endpoint: Endpoint::Socket(msg.client_addr),
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
                        endpoint: Endpoint::Socket(msg.client_addr),
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
        self.schedule_stream_key_purge(stream_key);
        if msg.report_to_counterpart {
            debug!(
                self.logger,
                "Reporting shutdown of {} to counterpart", &stream_key
            );
            let ibcd = InboundClientData {
                timestamp: SystemTime::now(),
                client_addr: msg.peer_addr,
                reception_port_opt: Some(nca.reception_port),
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
        }
    }

    fn find_or_generate_stream_key(&mut self, ibcd: &InboundClientData) -> StreamKey {
        match self.keys_and_addrs.b_to_a(&ibcd.client_addr) {
            Some(stream_key) => {
                debug!(
                    self.logger,
                    "find_or_generate_stream_key() retrieved existing key {} for {}",
                    &stream_key,
                    ibcd.client_addr
                );
                stream_key
            }
            None => {
                let stream_key = self
                    .stream_key_factory
                    .make(self.main_cryptde.public_key(), ibcd.client_addr);
                self.keys_and_addrs.insert(stream_key, ibcd.client_addr);
                self.stream_info.insert(
                    stream_key,
                    StreamInfo {
                        tunneled_host_opt: None,
                        dns_failure_retry_opt: None,
                        route_opt: None,
                        protocol_opt: None,
                        time_to_live_opt: None,
                    },
                );
                debug!(
                    self.logger,
                    "find_or_generate_stream_key() inserted new key {} for {}",
                    &stream_key,
                    ibcd.client_addr
                );
                stream_key
            }
        }
    }

    fn purge_stream_key(&mut self, stream_key: &StreamKey, reason: &str) {
        debug!(
            self.logger,
            "Retiring stream key {} due to {}", &stream_key, reason
        );
        let _ = self.keys_and_addrs.remove_a(stream_key);
        let _ = self.stream_info.remove(stream_key);
    }

    fn make_payload(
        &mut self,
        ibcd: InboundClientData,
        stream_key: &StreamKey,
    ) -> Result<ClientRequestPayload_0v1, String> {
        let stream_info_opt = self.stream_info.get(stream_key);
        let (host_opt, tunnelled_host_opt) = match stream_info_opt {
            None => (None, None),
            Some(info) => match &info.route_opt {
                Some(route) => (Some(route.host.clone()), info.tunneled_host_opt.clone()),
                None => (None, info.tunneled_host_opt.clone()),
            }
        };
        let new_ibcd = match tunnelled_host_opt {
            Some(_) => InboundClientData {
                reception_port_opt: Some(443),
                ..ibcd
            },
            None => ibcd,
        };
        match self.client_request_payload_factory.make(
            &new_ibcd,
            *stream_key,
            host_opt,
            self.alias_cryptde,
            &self.logger,
        ) {
            None => Err("Couldn't create ClientRequestPayload".to_string()),
            Some(payload) => match tunnelled_host_opt {
                Some(hostname) => Ok(ClientRequestPayload_0v1 {
                    target_hostname: hostname,
                    ..payload
                }),
                None => Ok(payload),
            },
        }
    }

    fn try_transmit_to_hopper(
        args: TransmitToHopperArgs,
        route_query_response: RouteQueryResponse,
    ) -> Result<(), String> {
        match route_query_response.expected_services {
            ExpectedServices::RoundTrip(over, _) => {
                ProxyServer::transmit_to_hopper(args, route_query_response.route, over)
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

    fn transmit_to_hopper(
        args: TransmitToHopperArgs,
        route: Route,
        expected_services: Vec<ExpectedService>,
    ) -> Result<(), String> {
        let logger = args.logger;
        let destination_key_opt = if args.is_decentralized {
            expected_services.iter().find_map(|service| match service {
                ExpectedService::Exit(public_key, _, _) => Some(public_key.clone()),
                _ => None,
            })
        } else {
            // In Zero Hop Mode the exit node public key is the same as this public key
            Some(args.main_cryptde.public_key().clone())
        };
        match destination_key_opt {
            None => {
                // Route not found
                Err(ProxyServer::handle_route_failure(
                    args.payload,
                    args.client_addr,
                    &args.dispatcher_sub,
                ))
            }
            Some(payload_destination_key) => {
                // Route found
                debug!(
                    logger,
                    "transmit to hopper with destination key {:?}", payload_destination_key
                );
                let payload = args.payload;
                let payload_size = payload.sequenced_packet.data.len();
                let stream_key = payload.stream_key;
                let pkg = IncipientCoresPackage::new(
                    args.main_cryptde,
                    route,
                    payload.into(),
                    &payload_destination_key,
                )
                .expect("Key magically disappeared");
                if args.is_decentralized {
                    let exit =
                        ProxyServer::report_on_exit_service(&expected_services, payload_size);
                    let routing =
                        ProxyServer::report_on_routing_services(expected_services, &logger);
                    args.accountant_sub
                        .try_send(ReportServicesConsumedMessage {
                            timestamp: args.timestamp,
                            exit,
                            routing_payload_size: pkg.payload.len(),
                            routing,
                        })
                        .expect("Accountant is dead");
                }
                args.hopper_sub.try_send(pkg).expect("Hopper is dead");
                if let Some(shutdown_sub) = args.retire_stream_key_sub_opt {
                    debug!(
                        logger,
                        "Last data is on the way; directing shutdown of stream {}", stream_key
                    );
                    shutdown_sub
                        .try_send(StreamShutdownMsg {
                            peer_addr: args.client_addr,
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
                Ok(())
            }
        }
    }

    fn handle_route_failure(
        payload: ClientRequestPayload_0v1,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
    ) -> String {
        let target_hostname = payload.target_hostname.clone();
        let stream_key = payload.stream_key;
        ProxyServer::send_route_failure(payload, source_addr, dispatcher);
        format!(
            "Failed to find route to {} for stream key: {}",
            target_hostname, stream_key
        )
    }

    fn send_route_failure(
        payload: ClientRequestPayload_0v1,
        source_addr: SocketAddr,
        dispatcher: &Recipient<TransmitDataMsg>,
    ) {
        let data = from_protocol(payload.protocol)
            .server_impersonator()
            .route_query_failure_response(&payload.target_hostname);
        let msg = TransmitDataMsg {
            endpoint: Endpoint::Socket(source_addr),
            last_data: true,
            sequence_number: Some(0),
            data,
        };
        dispatcher.try_send(msg).expect("Dispatcher is dead");
    }

    fn get_expected_return_services(
        &mut self,
        stream_key: &StreamKey,
    ) -> Option<Vec<ExpectedService>> {
        match self.stream_info(stream_key, &self.logger) {
            None => {
                error!(self.logger, "Can't pay for return services consumed: received response with unrecognized stream key {:?}. Ignoring", stream_key);
                None
            },
            Some(stream_info) => match &stream_info.route_opt {
                None => {
                    error!(self.logger, "Can't pay for return services consumed: stream_info contains no route for stream key {:?}", stream_key);
                    None
                },
                Some(route) => match route.expected_services {
                    ExpectedServices::RoundTrip(_, ref return_services) => Some(return_services.clone()),
                    _ => panic!("Internal error: ExpectedServices in ProxyServer for stream key {:?} is not RoundTrip", stream_key),
                }
            }
        }
    }

    fn report_response_services_consumed(
        &self,
        expected_services: &[ExpectedService],
        exit_size: usize,
        routing_size: usize,
    ) {
        let exit_service_report: ExitServiceSearch = expected_services
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
        let routing_service_reports = expected_services
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
        // TODO: I was wondering: could we just use msg.is_last_data here, instead of a whole different
        // parameter? Then I thought no, they're not the same: is_last_data means the client won't
        // send any more data, but we don't want to retire_stream_key until we've waited for any
        // straggling responses from the server, so that we can pay for them. However, it turns out
        // that if there is any such delay for straggling data, it's doesn't have anything to do with
        // retire_stream_key, because retire_stream_key is always equal to msg.is_last_data. So we
        // _could_ remove retire_stream_key and use msg.is_last_data, but I think the whole thing
        // ought to be rejiggered to wait for straggling data.
        retire_stream_key: bool,
    ) -> Result<(), String>;

    fn request_route_and_transmit(
        &self,
        args: TransmitToHopperArgs,
        route_source: Recipient<RouteQueryMessage>,
        proxy_server_sub: Recipient<AddRouteResultMessage>,
    );
}

trait RouteQueryResponseResolver: Send {
    fn resolve_message(
        &self,
        args: TransmitToHopperArgs,
        // add_return_route_sub: Recipient<AddReturnRouteMessage>,
        proxy_server_sub: Recipient<AddRouteResultMessage>,
        route_result_opt: Result<Option<RouteQueryResponse>, MailboxError>,
    );
}
struct RouteQueryResponseResolverReal {}

impl RouteQueryResponseResolver for RouteQueryResponseResolverReal {
    fn resolve_message(
        &self,
        args: TransmitToHopperArgs,
        proxy_server_sub: Recipient<AddRouteResultMessage>,
        route_result_opt: Result<Option<RouteQueryResponse>, MailboxError>,
    ) {
        let stream_key = args.payload.stream_key;
        let result = match route_result_opt {
            Ok(Some(route_query_response)) => {
                match ProxyServer::try_transmit_to_hopper(args, route_query_response.clone()) {
                    Ok(()) => Ok(route_query_response),
                    Err(e) => Err(e),
                }
            }
            Ok(None) => Err(ProxyServer::handle_route_failure(
                args.payload,
                args.client_addr,
                &args.dispatcher_sub,
            )),
            Err(e) => Err(format!(
                "Neighborhood refused to answer route request: {:?}",
                e
            )),
        };
        proxy_server_sub
            .try_send(AddRouteResultMessage { stream_key, result })
            .expect("ProxyServer is dead");
    }
}

trait RouteQueryResponseResolverFactory {
    fn make(&self) -> Box<dyn RouteQueryResponseResolver>;
}
struct RouteQueryResponseResolverFactoryReal {}

impl RouteQueryResponseResolverFactory for RouteQueryResponseResolverFactoryReal {
    fn make(&self) -> Box<dyn RouteQueryResponseResolver> {
        Box::new(RouteQueryResponseResolverReal {})
    }
}
struct IBCDHelperReal {
    factory: Box<dyn RouteQueryResponseResolverFactory>,
}

impl IBCDHelperReal {
    fn new() -> Self {
        Self {
            factory: Box::new(RouteQueryResponseResolverFactoryReal {}),
        }
    }
}

impl IBCDHelper for IBCDHelperReal {
    fn handle_normal_client_data(
        &self,
        proxy_server: &mut ProxyServer,
        msg: InboundClientData,
        retire_stream_key: bool,
    ) -> Result<(), String> {
        let client_addr = msg.client_addr;
        if proxy_server.consuming_wallet_balance.is_none() && proxy_server.is_decentralized {
            let protocol_pack = match from_ibcd(&msg) {
                Err(e) => return Err(e),
                Ok(pp) => pp,
            };
            let data = protocol_pack
                .server_impersonator()
                .consuming_wallet_absent();
            let msg = TransmitDataMsg {
                endpoint: Endpoint::Socket(client_addr),
                last_data: true,
                sequence_number: Some(0),
                data,
            };
            proxy_server
                .out_subs("Dispatcher")
                .dispatcher
                .try_send(msg)
                .expect("Dispatcher is dead");
            return Err("Browser request rejected due to missing consuming wallet".to_string());
        }
        let stream_key = proxy_server.find_or_generate_stream_key(&msg);
        let timestamp = msg.timestamp;
        let payload = match proxy_server.make_payload(msg, &stream_key) {
            Ok(payload) => {
                if !proxy_server.is_running_in_integration_test {
                    if let Err(e) = Hostname::new(&payload.target_hostname).validate_non_loopback_host() {
                        return Err(format!("Request to wildcard IP detected - {} (Most likely because Blockchain Service URL is not set)", e));
                    }
                }
                payload
            }
            Err(e) => return Err(e),
        };

        {
            let is_decentralized = proxy_server.is_decentralized;
            let mut stream_info = proxy_server
                .stream_info_mut(&stream_key)
                .unwrap_or_else(|| panic!("Stream key {} disappeared!", &stream_key));
            if stream_info.dns_failure_retry_opt.is_none() {
                let dns_failure_retry = DNSFailureRetry {
                    unsuccessful_request: payload.clone(),
                    retries_left: if is_decentralized {
                        DNS_FAILURE_RETRIES
                    } else {
                        0
                    },
                };
                stream_info.dns_failure_retry_opt = Some(dns_failure_retry);
                stream_info.protocol_opt = Some(payload.protocol);
            }
        }
        let args =
            TransmitToHopperArgs::new(proxy_server, payload, client_addr, timestamp, retire_stream_key);
        let pld = &args.payload;
        let stream_info = proxy_server
            .stream_info(&pld.stream_key, &proxy_server.logger)
            .unwrap_or_else(|| panic!("Stream key {} disappeared!", &pld.stream_key));
        if let Some(route_query_response) = &stream_info.route_opt {
            debug!(
                proxy_server.logger,
                "Transmitting down existing stream {}: sequence {}, length {}",
                pld.stream_key,
                pld.sequenced_packet.sequence_number,
                pld.sequenced_packet.data.len()
            );
            let route_query_response = route_query_response.clone();
            ProxyServer::try_transmit_to_hopper(args, route_query_response)
        } else {
            let route_source = proxy_server.out_subs("Neighborhood").route_source.clone();
            let proxy_server_sub = proxy_server.out_subs("ProxyServer").route_result_sub.clone();
            self.request_route_and_transmit(args, route_source, proxy_server_sub);
            Ok(())
        }
    }

    fn request_route_and_transmit(
        &self,
        args: TransmitToHopperArgs,
        neighborhood_sub: Recipient<RouteQueryMessage>,
        proxy_server_sub: Recipient<AddRouteResultMessage>,
    ) {
        let pld = &args.payload;
        let host = Host::new(&pld.target_hostname, pld.target_port);
        let logger = args.logger.clone();
        debug!(
            logger,
            "Getting route and opening new stream with key {} to transmit: sequence {}, length {}",
            pld.stream_key,
            pld.sequenced_packet.sequence_number,
            pld.sequenced_packet.data.len()
        );
        let payload_size = pld.sequenced_packet.data.len();
        let message_resolver = self.factory.make();

        tokio::spawn(
            neighborhood_sub
                .send(RouteQueryMessage::data_indefinite_route_request(
                    host,
                    payload_size,
                ))
                .then(move |route_result| {
                    message_resolver.resolve_message(args, proxy_server_sub, route_result);
                    Ok(())
                }),
        );
    }
}

pub struct TransmitToHopperArgs {
    pub main_cryptde: &'static dyn CryptDE,
    pub payload: ClientRequestPayload_0v1,
    pub client_addr: SocketAddr,
    pub timestamp: SystemTime,
    pub is_decentralized: bool,
    pub logger: Logger,
    pub retire_stream_key_sub_opt: Option<Recipient<StreamShutdownMsg>>,
    pub hopper_sub: Recipient<IncipientCoresPackage>,
    pub dispatcher_sub: Recipient<TransmitDataMsg>,
    pub accountant_sub: Recipient<ReportServicesConsumedMessage>,
}

impl TransmitToHopperArgs {
    pub fn new(
        proxy_server: &ProxyServer,
        payload: ClientRequestPayload_0v1,
        client_addr: SocketAddr,
        timestamp: SystemTime,
        retire_stream_key: bool,
    ) -> Self {
        let retire_stream_key_sub_opt = if retire_stream_key {
            Some(
                proxy_server
                    .out_subs("ProxyServer")
                    .stream_shutdown_sub
                    .clone(),
            )
        } else {
            None
        };
        Self {
            main_cryptde: proxy_server.main_cryptde,
            payload,
            client_addr,
            timestamp,
            logger: proxy_server.logger.clone(),
            retire_stream_key_sub_opt,
            hopper_sub: proxy_server.out_subs("Hopper").hopper.clone(),
            dispatcher_sub: proxy_server.out_subs("Dispatcher").dispatcher.clone(),
            accountant_sub: proxy_server.out_subs("Accountant").accountant.clone(),
            is_decentralized: proxy_server.is_decentralized,
        }
    }
}

enum ExitServiceSearch {
    Definite(ExitServiceConsumed),
    ZeroHop,
}

trait StreamKeyFactory: Send {
    fn make(&self, public_key: &PublicKey, client_addr: SocketAddr) -> StreamKey;
}

struct StreamKeyFactoryReal {}

impl StreamKeyFactory for StreamKeyFactoryReal {
    fn make(&self, public_key: &PublicKey, client_addr: SocketAddr) -> StreamKey {
        StreamKey::new(public_key, client_addr)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DNSFailureRetry {
    unsuccessful_request: ClientRequestPayload_0v1,
    retries_left: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Hostname {
    hostname: String,
}

impl Hostname {
    fn new(raw_url: &str) -> Self {
        let regex = Regex::new(
            r"^((http[s]?|ftp):/)?/?([^:/\s]+)((/\w+)*/)([\w\-.]+[^#?\s]+)(.*)?(#[\w\-]+)?$",
        )
        .expect("Bad Regex");
        let hostname = match regex.captures(raw_url) {
            None => raw_url.to_string(),
            Some(capture) => match capture.get(3) {
                None => raw_url.to_string(),
                Some(m) => m.as_str().to_string(),
            },
        };
        Self { hostname }
    }

    fn validate_non_loopback_host(&self) -> Result<(), String> {
        match IpAddr::from_str(&self.hostname) {
            Ok(ip_addr) => match ip_addr {
                IpAddr::V4(ipv4addr) => Self::validate_ipv4(ipv4addr),
                IpAddr::V6(ipv6addr) => Self::validate_ipv6(ipv6addr),
            },
            Err(_) => Self::validate_raw_string(&self.hostname),
        }
    }

    fn validate_ipv4(addr: Ipv4Addr) -> Result<(), String> {
        if addr.octets() == [0, 0, 0, 0] {
            Err("0.0.0.0".to_string())
        } else if addr.octets() == [127, 0, 0, 1] {
            Err("127.0.0.1".to_string())
        } else {
            Ok(())
        }
    }

    fn validate_ipv6(addr: Ipv6Addr) -> Result<(), String> {
        if addr.segments() == [0, 0, 0, 0, 0, 0, 0, 0] {
            Err("::".to_string())
        } else if addr.segments() == [0, 0, 0, 0, 0, 0, 0, 1] {
            Err("::1".to_string())
        } else {
            Ok(())
        }
    }

    fn validate_raw_string(name: &str) -> Result<(), String> {
        if name == "localhost" {
            Err("localhost".to_string())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::match_every_type_id;
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
    use crate::sub_lib::versioned_data::VersionedData;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::make_wallet;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder_stop_conditions::{StopCondition, StopConditions};
    use crate::test_utils::unshared_test_utils::{
        make_request_payload, prove_that_crash_request_handler_is_hooked_up, AssertionsMessage,
    };
    use crate::test_utils::zero_hop_route_response;
    use crate::test_utils::{alias_cryptde, rate_pack};
    use crate::test_utils::{main_cryptde, make_meaningless_route};
    use actix::System;
    use masq_lib::constants::{HTTP_PORT, TLS_PORT};
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::any::TypeId;
    use std::cell::RefCell;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::SystemTime;
    use crate::sub_lib::host::Host;

    impl Handler<AssertionsMessage<ProxyServer>> for ProxyServer {
        type Result = ();

        fn handle(
            &mut self,
            msg: AssertionsMessage<ProxyServer>,
            _ctx: &mut Self::Context,
        ) -> Self::Result {
            (msg.assertions)(self)
        }
    }

    #[derive(Default)]
    struct RouteQueryResponseResolverFactoryMock {
        make_params: Arc<Mutex<Vec<()>>>,
        make_results: RefCell<Vec<Box<dyn RouteQueryResponseResolver>>>,
    }
    impl RouteQueryResponseResolverFactory for RouteQueryResponseResolverFactoryMock {
        fn make(&self) -> Box<dyn RouteQueryResponseResolver> {
            self.make_params.lock().unwrap().push(());
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl RouteQueryResponseResolverFactoryMock {
        fn make_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
            self.make_params = params.clone();
            self
        }
        fn make_result(self, result: Box<dyn RouteQueryResponseResolver>) -> Self {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Default)]
    struct RouteQueryResponseResolverMock {
        resolve_message_params: Arc<
            Mutex<
                Vec<(
                    TransmitToHopperArgs,
                    Result<Option<RouteQueryResponse>, MailboxError>,
                )>,
            >,
        >,
    }

    impl RouteQueryResponseResolver for RouteQueryResponseResolverMock {
        fn resolve_message(
            &self,
            args: TransmitToHopperArgs,
            _proxy_server_sub: Recipient<AddRouteResultMessage>,
            route_result: Result<Option<RouteQueryResponse>, MailboxError>,
        ) {
            self.resolve_message_params
                .lock()
                .unwrap()
                .push((args, route_result));
        }
    }

    impl RouteQueryResponseResolverMock {
        fn resolve_message_params(
            mut self,
            param: &Arc<
                Mutex<
                    Vec<(
                        TransmitToHopperArgs,
                        Result<Option<RouteQueryResponse>, MailboxError>,
                    )>,
                >,
            >,
        ) -> Self {
            self.resolve_message_params = param.clone();
            self
        }
    }

    struct StreamInfoBuilder {
        product: StreamInfo,
    }

    impl StreamInfoBuilder {
        pub fn new() -> Self {
            Self {
                product: StreamInfo {
                    tunneled_host_opt: None,
                    dns_failure_retry_opt: None,
                    route_opt: None,
                    protocol_opt: None,
                    time_to_live_opt: None,
                },
            }
        }

        pub fn tunneled_host(mut self, host: &str) -> Self {
            self.product.tunneled_host_opt = Some(host.to_string());
            self
        }

        pub fn dns_failure_retry(mut self, retry: DNSFailureRetry) -> Self {
            self.product.dns_failure_retry_opt = Some(retry);
            self
        }

        pub fn route(mut self, route: RouteQueryResponse) -> Self {
            self.product.route_opt = Some(route);
            self
        }

        pub fn protocol(mut self, protocol: ProxyProtocol) -> Self {
            self.product.protocol_opt = Some(protocol);
            self
        }

        pub fn time_to_live(mut self, ttl: SystemTime) -> Self {
            self.product.time_to_live_opt = Some(ttl);
            self
        }

        pub fn build(self) -> StreamInfo {
            self.product
        }
    }

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "PROXYSERVER");
        assert_eq!(RETURN_ROUTE_TTL_FIRST_CHANCE, Duration::from_secs(120));
        assert_eq!(RETURN_ROUTE_TTL_STRAGGLERS, Duration::from_secs(5));
        assert_eq!(STREAM_KEY_PURGE_DELAY, Duration::from_secs(30));
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
            update_node_record_metadata: recipient!(addr, UpdateNodeRecordMetadataMessage),
            stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
            route_result_sub: recipient!(addr, AddRouteResultMessage),
            schedule_stream_key_purge: recipient!(addr, MessageScheduler<StreamKeyPurge>),
        }
    }

    struct StreamKeyFactoryMock {
        make_parameters: Arc<Mutex<Vec<(PublicKey, SocketAddr)>>>,
        make_results: RefCell<Vec<StreamKey>>,
    }

    impl StreamKeyFactory for StreamKeyFactoryMock {
        fn make(&self, public_key: &PublicKey, client_addr: SocketAddr) -> StreamKey {
            self.make_parameters
                .lock()
                .unwrap()
                .push((public_key.clone(), client_addr));
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

        fn request_route_and_transmit(
            &self,
            _args: TransmitToHopperArgs,
            _route_source: Recipient<RouteQueryMessage>,
            _proxy_server_sub: Recipient<AddRouteResultMessage>,
        ) {
            unimplemented!();
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
    fn get_expected_services_produces_nothing_if_nothing_exists() {
        let mut subject = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        let stream_key = StreamKey::make_meaningless_stream_key();

        let result = subject.get_expected_return_services(&stream_key);

        assert!(
            result.is_none(),
            "Expected no expected services, but got: {:?}",
            result
        );
    }

    #[test]
    fn get_expected_services_produces_rri_when_it_exists() {
        let mut subject = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        let exit_public_key = PublicKey::new(&b"exit key"[..]);
        let stream_key = StreamKey::make_meaningless_stream_key();
        let back_services = vec![ExpectedService::Exit(
            exit_public_key,
            make_wallet("booga"),
            rate_pack(1000),
        )];
        let expected_services = ExpectedServices::RoundTrip(vec![], back_services.clone());
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: make_meaningless_route(),
                    expected_services: expected_services.clone(),
                    host: Host::new("booga.com", TLS_PORT),
                })
                .protocol(ProxyProtocol::TLS)
                .build(),
        );

        let result = subject.get_expected_return_services(&stream_key).unwrap();

        assert_eq!(result, back_services);
    }

    #[test]
    fn proxy_server_receives_http_request_with_new_stream_key_from_dispatcher_then_sends_cores_package_to_hopper(
    ) {
        init_test_logging();
        let test_name = "proxy_server_receives_http_request_with_new_stream_key_from_dispatcher_then_sends_cores_package_to_hopper";
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
            ),
            host: Host::new("booga.com", HTTP_PORT),
        }));
        let (proxy_server_mock, _, proxy_server_recording_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr,
            reception_port_opt: Some(HTTP_PORT),
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
            target_hostname: String::from("nowhere.com"),
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
                .make_result(stream_key.clone());
            let system = System::new(test_name);
            let mut subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
                false,
            );
            subject.logger = Logger::new(test_name);
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

            subject_addr
                .try_send(AssertionsMessage {
                    assertions: Box::new(move |proxy_server: &mut ProxyServer| {
                        assert!(proxy_server.stream_info.contains_key(&stream_key));
                    }),
                })
                .unwrap();
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
            &RouteQueryMessage::data_indefinite_route_request(Host::new("nowhere.com", HTTP_PORT), 47)
        );
        let recording = proxy_server_recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);

        TestLogHandler::new().exists_log_containing(
            &format!("DEBUG: {test_name}: Found a new route for hostname: \"nowhere.com\" - stream key: {stream_key}  retries left: 3")
        );
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
            ),
            host: Host::new("booga.com", HTTP_PORT),
        }));
        let route = Route { hops: vec![] };
        let (dispatcher_mock, _, dispatcher_recording_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let request_data = http_request.to_vec();
        let tunneled_data = make_server_com_client_hello();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(8443),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: request_data.clone(),
        };
        let tunnelled_msg = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr,
            reception_port_opt: Some(8443),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: tunneled_data.clone(),
        };
        let expected_tdm = TransmitDataMsg {
            endpoint: Endpoint::Socket(socket_addr),
            last_data: false,
            sequence_number: Some(0),
            data: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
        };
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: tunneled_data,
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: String::from("realdomain.nu"),
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
        let make_parameters_arc = Arc::new(Mutex::new(vec![]));
        let make_parameters_arc_thread = make_parameters_arc.clone();

        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new()
                .make_parameters(&make_parameters_arc_thread)
                .make_result(stream_key.clone());
            let system = System::new(
                "proxy_server_receives_connect_responds_with_ok_and_stores_stream_key_and_hostname",
            );
            let mut subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
                false,
            );
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .dispatcher(dispatcher_mock)
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();
            subject_addr.try_send(tunnelled_msg).unwrap();
            subject_addr
                .try_send(AssertionsMessage {
                    assertions: Box::new(move |proxy_server: &mut ProxyServer| {
                        assert!(proxy_server.stream_info.contains_key(&stream_key));
                    }),
                })
                .unwrap();
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
                Host::new("realdomain.nu", TLS_PORT),
                68
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
            false,
        );
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject
            .stream_info
            .insert(stream_key.clone(), StreamInfoBuilder::new().build());
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: make_meaningless_route(),
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![ExpectedService::Nothing],
                    ),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .build(),
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let http_request = b"CONNECT https://realdomain.nu:443 HTTP/1.1\r\nHost: https://bunkjunk.wrong:443\r\n\r\n";
        let request_data = http_request.to_vec();
        let inbound_client_data = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr,
            reception_port_opt: Some(443),
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

        let peer_actors = peer_actors_builder().dispatcher(dispatcher_mock).build();
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
            zero_hop_route_response(&cryptde.public_key(), cryptde, false),
        ));

        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let request_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(8443),
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
                false,
            );
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .dispatcher(dispatcher_mock)
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
            zero_hop_route_response(&cryptde.public_key(), cryptde, false),
        ));

        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let request_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(8443),
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
                false,
            );
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .dispatcher(dispatcher_mock)
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
        let system = System::new("proxy_server_receives_http_request_with_no_consuming_wallet_and_sends_impersonated_response");
        let mut subject = ProxyServer::new(cryptde, alias_cryptde(), true, None, false, false);
        subject.stream_key_factory = Box::new(stream_key_factory);
        subject.keys_and_addrs.insert(stream_key, socket_addr);
        let subject_addr: Addr<ProxyServer> = subject.start();
        let peer_actors = peer_actors_builder()
            .dispatcher(dispatcher)
            .hopper(hopper)
            .neighborhood(neighborhood)
            .build();
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
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
        let system = System::new("proxy_server_receives_tls_request_with_no_consuming_wallet_and_sends_impersonated_response");
        let mut subject = ProxyServer::new(cryptde, alias_cryptde(), true, None, false, false);
        subject.stream_key_factory = Box::new(stream_key_factory);
        subject.keys_and_addrs.insert(stream_key, socket_addr);
        let subject_addr: Addr<ProxyServer> = subject.start();
        let peer_actors = peer_actors_builder()
            .dispatcher(dispatcher)
            .hopper(hopper)
            .neighborhood(neighborhood)
            .build();
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
        let expected_route = zero_hop_route_response(main_cryptde.public_key(), main_cryptde, false);
        let stream_key = StreamKey::make_meaningless_stream_key();
        let (hopper, hopper_awaiter, hopper_log_arc) = make_recorder();
        let neighborhood = Recorder::new().route_query_response(Some(expected_route.clone()));
        let neighborhood_log_arc = neighborhood.get_recording();
        let (dispatcher, _, dispatcher_log_arc) = make_recorder();
        thread::spawn(move || {
            let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
            let msg_from_dispatcher = InboundClientData {
                timestamp: SystemTime::now(),
                client_addr: socket_addr.clone(),
                reception_port_opt: Some(HTTP_PORT),
                sequence_number: Some(0),
                last_data: true,
                is_clandestine: false,
                data: expected_data_inner,
            };
            let stream_key_factory = StreamKeyFactoryMock::new(); // can't make any stream keys; shouldn't have to
            let system = System::new("proxy_server_receives_http_request_with_no_consuming_wallet_in_zero_hop_mode_and_handles_normally");
            let mut subject =
                ProxyServer::new(main_cryptde, alias_cryptde, false, None, false, false);
            subject.stream_key_factory = Box::new(stream_key_factory);
            subject
                .keys_and_addrs
                .insert(stream_key.clone(), socket_addr);
            subject
                .stream_info
                .insert(stream_key, StreamInfoBuilder::new().build());
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .dispatcher(dispatcher)
                .hopper(hopper)
                .neighborhood(neighborhood)
                .build();
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
                host: Host::new("nowhere.com", HTTP_PORT),
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
                        target_hostname: "nowhere.com".to_string(),
                        target_port: HTTP_PORT,
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
        let expected_route = zero_hop_route_response(main_cryptde.public_key(), main_cryptde, true);
        let expected_route_inner = expected_route.clone();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let (hopper, hopper_awaiter, hopper_log_arc) = make_recorder();
        let neighborhood = Recorder::new().route_query_response(Some(expected_route.clone()));
        let (dispatcher, _, dispatcher_log_arc) = make_recorder();
        thread::spawn(move || {
            let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
            let msg_from_dispatcher = InboundClientData {
                timestamp: SystemTime::now(),
                client_addr: socket_addr.clone(),
                reception_port_opt: Some(TLS_PORT),
                sequence_number: Some(0),
                last_data: true,
                is_clandestine: false,
                data: expected_data_inner,
            };
            let stream_key_factory = StreamKeyFactoryMock::new()
                .make_result(stream_key.clone());
            let system = System::new("proxy_server_receives_tls_request_with_no_consuming_wallet_in_zero_hop_mode_and_handles_normally");
            let mut subject =
                ProxyServer::new(main_cryptde, alias_cryptde, false, None, false, false);
            subject.stream_key_factory = Box::new(stream_key_factory);
            subject.keys_and_addrs.insert(stream_key, socket_addr);
            subject
                .stream_info
                .insert(stream_key, StreamInfoBuilder::new()
                    .route(expected_route_inner)
                    .protocol(ProxyProtocol::TLS)
                    .build());
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .dispatcher(dispatcher)
                .hopper(hopper)
                .neighborhood(neighborhood)
                .build();
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });
        hopper_awaiter.await_message_count(1);
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
                        target_hostname: "booga.com".to_string(),
                        target_port: TLS_PORT,
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
            ),
            host: Host::new("booga.com", HTTP_PORT),
        }));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
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
            target_hostname: String::from("nowhere.com"),
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
                false,
            );
            subject.stream_key_factory = Box::new(stream_key_factory);
            subject.keys_and_addrs.insert(stream_key, socket_addr);
            subject
                .stream_info
                .insert(stream_key.clone(), StreamInfoBuilder::new().build());
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
            ),
            host: Host::new("booga.com", HTTP_PORT),
        }));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
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
            target_hostname: String::from("nowhere.com"),
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
            let system = System::new("proxy_server_receives_http_request_from_dispatcher_then_sends_multihop_cores_package_to_hopper");
            let mut subject = ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
                false,
            );
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
            &RouteQueryMessage::data_indefinite_route_request(Host::new("nowhere.com", HTTP_PORT), 47)
        );
    }

    #[test]
    fn proxy_server_sends_a_message_when_dns_retry_found_a_route() {
        let cryptde = main_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (proxy_server_mock, proxy_server_awaiter, proxy_server_recording_arc) = make_recorder();
        let expected_service = ExpectedService::Exit(
            main_cryptde().public_key().clone(),
            make_wallet("walletAddress"),
            DEFAULT_RATE_PACK,
        );
        let route_query_response = Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![expected_service.clone()],
                vec![expected_service],
            ),
            host: Host::new("booga.com", HTTP_PORT),
        });
        let (neighborhood_mock, _, _) = make_recorder();
        let neighborhood_mock =
            neighborhood_mock.route_query_response(route_query_response.clone());
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };

        thread::spawn(move || {
            let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
            let system = System::new("proxy_server_sends_a_message_when_dns_retry_found_a_route");
            let mut subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
                false,
            );
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let mut peer_actors = peer_actors_builder()
                .proxy_server(proxy_server_mock)
                .neighborhood(neighborhood_mock)
                .build();
            // Get the dns_retry_result recipient so we can partially mock it...
            let dns_retry_result_recipient = peer_actors.proxy_server.route_result_sub;
            peer_actors.proxy_server = ProxyServer::make_subs_from(&subject_addr);
            peer_actors.proxy_server.route_result_sub = dns_retry_result_recipient; //Partial mocking
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();

            subject_addr.try_send(msg_from_dispatcher).unwrap();

            system.run();
        });
        let expected_route_result_message = AddRouteResultMessage {
            stream_key,
            result: Ok(route_query_response.unwrap()),
        };
        proxy_server_awaiter.await_message_count(1);
        let recording = proxy_server_recording_arc.lock().unwrap();
        let message = recording.get_record::<AddRouteResultMessage>(0);
        assert_eq!(message, &expected_route_result_message);
    }

    #[test]
    fn proxy_server_sends_a_message_when_dns_retry_cannot_find_a_route() {
        let test_name = "proxy_server_sends_a_message_when_dns_retry_cannot_find_a_route";
        let cryptde = main_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (proxy_server_mock, _, proxy_server_recording_arc) = make_recorder();
        let proxy_server_mock =
            proxy_server_mock.system_stop_conditions(match_every_type_id!(AddRouteResultMessage));
        let route_query_response = None;
        let (neighborhood_mock, _, _) = make_recorder();
        let neighborhood_mock =
            neighborhood_mock.route_query_response(route_query_response.clone());
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
        let system = System::new(test_name);
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        subject.logger = Logger::new(test_name);
        subject.stream_key_factory = Box::new(stream_key_factory);
        let subject_addr: Addr<ProxyServer> = subject.start();
        let mut peer_actors = peer_actors_builder()
            .proxy_server(proxy_server_mock)
            .neighborhood(neighborhood_mock)
            .build();
        // Get the dns_retry_result recipient so we can partially mock it...
        let dns_retry_result_recipient = peer_actors.proxy_server.route_result_sub;
        peer_actors.proxy_server.route_result_sub = dns_retry_result_recipient; //Partial mocking
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(msg_from_dispatcher).unwrap();

        system.run();
        let recording = proxy_server_recording_arc.lock().unwrap();
        let message = recording.get_record::<AddRouteResultMessage>(0);
        assert_eq!(message.stream_key, stream_key);
        assert_eq!(
            message.result,
            Err(format!(
                "Failed to find route to nowhere.com for stream key: {stream_key}"
            ))
        );
    }

    #[test]
    fn proxy_server_sends_a_message_with_error_when_quad_zeros_are_detected() {
        init_test_logging();
        let test_name = "proxy_server_sends_a_message_with_error_when_quad_zeros_are_detected";
        let cryptde = main_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: 0.0.0.0\r\n\r\n";
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key);
        let system = System::new(test_name);
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        subject.stream_key_factory = Box::new(stream_key_factory);
        subject.logger = Logger::new(test_name);
        let subject_addr: Addr<ProxyServer> = subject.start();
        let peer_actors = peer_actors_builder().build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(msg_from_dispatcher).unwrap();

        System::current().stop();
        system.run();

        TestLogHandler::new().exists_log_containing(&format!("ERROR: {test_name}: Request to wildcard IP detected - 0.0.0.0 (Most likely because Blockchain Service URL is not set)"));
    }

    #[test]
    fn proxy_server_uses_existing_route() {
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let route = Route { hops: vec![] };
        let route_with_rrid = route.clone();
        let route_query_response = RouteQueryResponse {
            route,
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
            ),
            host: Host::new("booga.com", HTTP_PORT),
        };
        let (hopper_mock, hopper_awaiter, hopper_recording_arc) = make_recorder();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr,
            reception_port_opt: Some(HTTP_PORT),
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
            target_hostname: String::from("nowhere.com"),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: alias_cryptde.public_key().clone(),
        };
        let expected_pkg = IncipientCoresPackage::new(
            main_cryptde,
            route_with_rrid,
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
                false,
            );
            subject.stream_key_factory = Box::new(stream_key_factory);
            subject
                .keys_and_addrs
                .insert(stream_key.clone(), socket_addr);
            subject.stream_info.insert(
                stream_key,
                StreamInfoBuilder::new().route(route_query_response).build(),
            );
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder().hopper(hopper_mock).build();
            subject_addr.try_send(BindMessage { peer_actors }).unwrap();
            subject_addr.try_send(msg_from_dispatcher).unwrap();

            System::current().stop();
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
        let routing_node_1_public_key = PublicKey::new(&[1]);
        let routing_node_2_public_key = PublicKey::new(&[2]);
        let exit_node_public_key = PublicKey::new(&[3]);
        let key_bytes = b"__originating consuming wallet__";
        let keypair = Bip32EncryptionKeyProvider::from_raw_secret(key_bytes).unwrap();
        let originating_consuming_wallet = Wallet::from(keypair);
        let routing_node_1_earning_wallet = make_wallet("route 1 earning wallet");
        let routing_node_2_earning_wallet = make_wallet("route 2 earning wallet");
        let exit_node_earning_wallet = make_wallet("exit earning wallet");
        let routing_node_1_rate_pack = rate_pack(101);
        let routing_node_2_rate_pack = rate_pack(102);
        let exit_node_rate_pack = rate_pack(103);
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (accountant_mock, _, accountant_recording_arc) = make_recorder();
        let (hopper_mock, _, hopper_recording_arc) = make_recorder();
        let (proxy_server_mock, _, proxy_server_recording_arc) = make_recorder();
        let over_route_segment = RouteSegment::new(
            vec![
                &cryptde.public_key(),
                &routing_node_1_public_key,
                &routing_node_2_public_key,
                &exit_node_public_key,
            ],
            Component::ProxyClient,
        );
        let back_route_segment = RouteSegment::new(
            vec![
                &exit_node_public_key,
                &routing_node_2_public_key,
                &routing_node_1_public_key,
                &cryptde.public_key(),
            ],
            Component::ProxyServer,
        );
        let route = Route::round_trip(
            over_route_segment,
            back_route_segment,
            cryptde,
            Some(originating_consuming_wallet),
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();
        let route_query_response = RouteQueryResponse {
            route,
            expected_services: ExpectedServices::RoundTrip(
                vec![
                    ExpectedService::Nothing,
                    ExpectedService::Routing(
                        routing_node_1_public_key.clone(),
                        routing_node_1_earning_wallet.clone(),
                        routing_node_1_rate_pack.clone(),
                    ),
                    ExpectedService::Routing(
                        routing_node_2_public_key.clone(),
                        routing_node_2_earning_wallet.clone(),
                        routing_node_2_rate_pack.clone(),
                    ),
                    ExpectedService::Exit(
                        exit_node_public_key.clone(),
                        exit_node_earning_wallet.clone(),
                        exit_node_rate_pack.clone(),
                    ),
                ],
                vec![
                    ExpectedService::Exit(
                        exit_node_public_key.clone(),
                        exit_node_earning_wallet.clone(),
                        exit_node_rate_pack,
                    ),
                    ExpectedService::Routing(
                        routing_node_2_public_key.clone(),
                        routing_node_2_earning_wallet.clone(),
                        routing_node_2_rate_pack,
                    ),
                    ExpectedService::Routing(
                        routing_node_1_public_key.clone(),
                        routing_node_1_earning_wallet.clone(),
                        routing_node_1_rate_pack,
                    ),
                    ExpectedService::Nothing,
                ],
            ),
            host: Host::new("booga.com", HTTP_PORT),
        };
        let source_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
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
            target_hostname: "nowhere.com".to_string(),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(b"originator_public_key"),
        };
        let logger = Logger::new("test");
        let args = TransmitToHopperArgs {
            main_cryptde: cryptde,
            payload,
            client_addr: source_addr,
            timestamp: now,
            is_decentralized: true,
            logger,
            hopper_sub: peer_actors.hopper.from_hopper_client,
            dispatcher_sub: peer_actors.dispatcher.from_dispatcher_client,
            accountant_sub: peer_actors.accountant.report_services_consumed,
            retire_stream_key_sub_opt: None,
        };

        let result = ProxyServer::try_transmit_to_hopper(args, route_query_response);

        System::current().stop();
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        let mut record = recording.get_record::<IncipientCoresPackage>(0).clone();
        let payload_enc_length = record.payload.len();
        let _ = record.route.shift(cryptde);
        let _ = record.route.shift(&CryptDENull::from(
            &routing_node_1_public_key,
            TEST_DEFAULT_CHAIN,
        ));
        let _ = record.route.shift(&CryptDENull::from(
            &routing_node_2_public_key,
            TEST_DEFAULT_CHAIN,
        ));
        let _ = record.route.shift(&CryptDENull::from(
            &exit_node_public_key,
            TEST_DEFAULT_CHAIN,
        ));
        let _ = record.route.shift(&CryptDENull::from(
            &routing_node_2_public_key,
            TEST_DEFAULT_CHAIN,
        ));
        let _ = record.route.shift(&CryptDENull::from(
            &routing_node_1_public_key,
            TEST_DEFAULT_CHAIN,
        ));
        let _ = record.route.shift(cryptde);
        let recording = accountant_recording_arc.lock().unwrap();
        let record = recording.get_record::<ReportServicesConsumedMessage>(0);
        assert_eq!(recording.len(), 1);
        assert_eq!(
            record,
            &ReportServicesConsumedMessage {
                timestamp: now,
                exit: ExitServiceConsumed {
                    earning_wallet: exit_node_earning_wallet,
                    payload_size: exit_payload_size,
                    service_rate: exit_node_rate_pack.exit_service_rate,
                    byte_rate: exit_node_rate_pack.exit_byte_rate
                },
                routing_payload_size: payload_enc_length,
                routing: vec![
                    RoutingServiceConsumed {
                        earning_wallet: routing_node_1_earning_wallet,
                        service_rate: routing_node_1_rate_pack.routing_service_rate,
                        byte_rate: routing_node_1_rate_pack.routing_byte_rate,
                    },
                    RoutingServiceConsumed {
                        earning_wallet: routing_node_2_earning_wallet,
                        service_rate: routing_node_2_rate_pack.routing_service_rate,
                        byte_rate: routing_node_2_rate_pack.routing_byte_rate,
                    }
                ]
            }
        );
        let recording = proxy_server_recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0); // No StreamShutdownMsg: that's the important thing
        assert_eq!(result, Ok(()));
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
            ),
            host: Host::new("booga.com", HTTP_PORT),
        };
        let source_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let system =
            System::new("proxy_server_sends_message_to_accountant_for_routing_service_consumed");
        let peer_actors = peer_actors_builder()
            .proxy_server(proxy_server_mock)
            .build();
        let payload = ClientRequestPayload_0v1 {
            stream_key,
            sequenced_packet: SequencedPacket::new(expected_data, 0, false),
            target_hostname: "nowhere.com".to_string(),
            target_port: HTTP_PORT,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: PublicKey::new(b"originator_public_key"),
        };
        let logger = Logger::new("test");
        let args = TransmitToHopperArgs {
            main_cryptde: cryptde,
            payload,
            client_addr: source_addr,
            timestamp: SystemTime::now(),
            is_decentralized: false,
            logger,
            hopper_sub: peer_actors.hopper.from_hopper_client,
            dispatcher_sub: peer_actors.dispatcher.from_dispatcher_client,
            accountant_sub: peer_actors.accountant.report_services_consumed,
            retire_stream_key_sub_opt: Some(peer_actors.proxy_server.stream_shutdown_sub),
        };

        let result = ProxyServer::try_transmit_to_hopper(args, route_query_response);

        System::current().stop();
        system.run();
        let recording = proxy_server_recording_arc.lock().unwrap();
        let record = recording.get_record::<StreamShutdownMsg>(0);
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
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn proxy_server_logs_messages_when_routing_services_are_not_requested() {
        init_test_logging();
        let cryptde = main_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (accountant_mock, accountant_awaiter, _) = make_recorder();
        let (neighborhood_mock, _, _) = make_recorder();
        let mut route_query_response = zero_hop_route_response(&cryptde.public_key(), cryptde, false);
        route_query_response.expected_services = ExpectedServices::RoundTrip(
            vec![ExpectedService::Exit(
                cryptde.public_key().clone(),
                make_wallet("exit wallet"),
                rate_pack(3),
            )],
            vec![],
        );
        let neighborhood_mock =
            neighborhood_mock.route_query_response(Some(route_query_response.clone()));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
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
                false,
            );
            subject.stream_key_factory = Box::new(stream_key_factory);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .accountant(accountant_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
        expected = "AddRouteResultMessage Handler: dns_failure_retry_opt is None for stream key"
    )]
    fn route_result_message_handler_panics_when_no_dns_retries_exist() {
        init_test_logging();
        let system = System::new("route_result_message_handler_panics_when_no_dns_retries_exist");
        let mut subject = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        let stream_key = StreamKey::make_meaningless_stream_key();
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new().build(), // no DNS retries
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let peer_actors = peer_actors_builder().build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(AddRouteResultMessage {
                stream_key,
                result: Err("Some Error".to_string()),
            })
            .unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(&format!("ERROR: ProxyServer: No dns_failure_retry found for stream key {stream_key} while handling AddRouteResultMessage"));
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
        let test_name =
            "proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route";
        let cryptde = main_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let neighborhood_mock = neighborhood_mock.route_query_response(None);
        let dispatcher = Recorder::new();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = http_request.to_vec();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            data: expected_data.clone(),
            is_clandestine: false,
        };
        thread::spawn(move || {
            let system = System::new(test_name);
            let mut subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
                false,
            );
            subject.stream_key_factory =
                Box::new(StreamKeyFactoryMock::new().make_result(stream_key));
            subject.logger = Logger::new(test_name);
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
            &RouteQueryMessage::data_indefinite_route_request(Host::new("nowhere.com", HTTP_PORT), 47)
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: No route found for hostname: \"nowhere.com\" - stream key {stream_key} - retries left: 3 - AddRouteResultMessage Error: Failed to find route to nowhere.com"
        ));
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
            host: Host::new("booga.com", HTTP_PORT),
        };
        let payload = ClientRequestPayload_0v1 {
            stream_key: StreamKey::make_meaningless_stream_key(),
            sequenced_packet: SequencedPacket {
                data: vec![],
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: "booga.com".to_string(),
            target_port: 0,
            protocol: ProxyProtocol::TLS,
            originator_public_key: cryptde.public_key().clone(),
        };
        let logger = Logger::new("ProxyServer");
        let source_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let args = TransmitToHopperArgs {
            main_cryptde: cryptde,
            payload,
            client_addr: source_addr,
            timestamp: SystemTime::now(),
            is_decentralized: true,
            logger,
            hopper_sub: peer_actors.hopper.from_hopper_client,
            dispatcher_sub: peer_actors.dispatcher.from_dispatcher_client,
            accountant_sub: peer_actors.accountant.report_services_consumed,
            retire_stream_key_sub_opt: None,
        };

        let _result = ProxyServer::try_transmit_to_hopper(args, route_result);
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
            false,
        );
        let expected_services = vec![
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
        ];

        subject.report_response_services_consumed(&expected_services, 1234, 3456);
    }

    #[test]
    fn proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route_with_no_expected_services(
    ) {
        init_test_logging();
        let test_name = "proxy_server_receives_http_request_from_dispatcher_but_neighborhood_cant_make_route_with_no_expected_services";
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
                None,
            )
            .unwrap(),
            expected_services: ExpectedServices::RoundTrip(vec![], vec![]),
            host: Host::new("booga.com", HTTP_PORT),
        };
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(route_query_response));
        let dispatcher = Recorder::new();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            data: expected_data.clone(),
            is_clandestine: false,
        };
        let stream_key = StreamKey::make_meaningless_stream_key();
        thread::spawn(move || {
            let system = System::new(test_name);
            let mut subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
                false,
            );
            subject.logger = Logger::new(test_name);
            subject.stream_key_factory =
                Box::new(StreamKeyFactoryMock::new().make_result(stream_key));
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
            &RouteQueryMessage::data_indefinite_route_request(Host::new("nowhere.com", HTTP_PORT), 47)
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "WARN: {test_name}: No route found for hostname: \"nowhere.com\" - stream key {stream_key} - retries left: 3 - AddRouteResultMessage Error: Failed to find route to nowhere.com"
        ));
    }

    #[test]
    fn proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper() {
        let tls_request = make_server_com_client_hello();
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
            ),
            host: Host::new("booga.com", TLS_PORT),
        }));
        let stream_key = StreamKey::make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.clone();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: false,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_tls_request = PlainData::new(tls_request.as_slice());
        let route = Route { hops: vec![] };
        let expected_payload = ClientRequestPayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: expected_tls_request.into(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: String::from("server.com"),
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
                false,
            );
            subject.stream_key_factory =
                Box::new(StreamKeyFactoryMock::new().make_result(stream_key.clone()));
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
            ),
            host: Host::new("booga.com", TLS_PORT),
        }));
        let stream_key = StreamKey::make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(TLS_PORT),
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
            target_hostname: "booga.com".to_string(),
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
                false,
            );
            subject.stream_key_factory =
                Box::new(StreamKeyFactoryMock::new().make_result(stream_key.clone()));
            subject.keys_and_addrs.insert(stream_key.clone(), socket_addr);
            subject.stream_info.insert(
                stream_key.clone(),
                StreamInfoBuilder::new()
                    .route(RouteQueryResponse {
                        route: Route { hops: vec![] },
                        expected_services: ExpectedServices::RoundTrip(
                            vec![make_exit_service_from_key(destination_key.clone())],
                            vec![],
                        ),
                        host: Host::new("booga.com", TLS_PORT),
                    })
                    .build(),
            );
            let system = System::new("proxy_server_receives_tls_client_hello_from_dispatcher_then_sends_cores_package_to_hopper");
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
        let test_name = "proxy_server_receives_tls_packet_other_than_handshake_from_dispatcher_then_sends_cores_package_to_hopper";
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
            ),
            host: Host::new("booga.com", TLS_PORT),
        }));
        let client_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let expected_data = tls_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr,
            reception_port_opt: Some(TLS_PORT),
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
            target_hostname: "booga.com".to_string(),
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
                false,
            );
            subject.keys_and_addrs.insert(stream_key, client_addr);
            subject
                .stream_info
                .insert(stream_key, StreamInfoBuilder::new()
                    .route(RouteQueryResponse {
                        route: Route { hops: vec![] },
                        expected_services: ExpectedServices::RoundTrip(
                            vec![make_exit_service_from_key(destination_key.clone())],
                            vec![],
                        ),
                        host: Host::new("booga.com", TLS_PORT),
                    })
                    .protocol(ProxyProtocol::TLS)
                    .build());
            let system = System::new(test_name);
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .hopper(hopper_mock)
                .neighborhood(neighborhood_mock)
                .build();
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
        let test_name = "proxy_server_receives_tls_client_hello_from_dispatcher_but_neighborhood_cant_make_route";
        let dispatcher = Recorder::new();
        let dispatcher_awaiter = dispatcher.get_awaiter();
        let dispatcher_recording_arc = dispatcher.get_recording();
        let neighborhood = Recorder::new().route_query_response(None);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(TLS_PORT),
            sequence_number: Some(0),
            last_data: true,
            data: tls_request,
            is_clandestine: false,
        };
        thread::spawn(move || {
            let system = System::new(test_name);
            let mut subject = ProxyServer::new(
                cryptde,
                alias_cryptde(),
                true,
                Some(STANDARD_CONSUMING_WALLET_BALANCE),
                false,
                false,
            );
            subject.logger = Logger::new(test_name);
            subject.stream_key_factory =
                Box::new(StreamKeyFactoryMock::new().make_result(stream_key));
            let subject_addr: Addr<ProxyServer> = subject.start();
            let peer_actors = peer_actors_builder()
                .dispatcher(dispatcher)
                .neighborhood(neighborhood)
                .build();
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
    }

    #[test]
    fn proxy_server_receives_terminal_response_from_hopper() {
        init_test_logging();
        let test_name = "proxy_server_receives_terminal_response_from_hopper";
        let system = System::new(test_name);
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        subject.logger = Logger::new(test_name);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![ExpectedService::Nothing],
                    ),
                    host: Host::new("booga.com", TLS_PORT),
                })
                .protocol(ProxyProtocol::TLS)
                .build(),
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let remaining_route = return_route_with_id(cryptde, 0);
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
        let peer_actors = peer_actors_builder().dispatcher(dispatcher).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(first_expired_cores_package).unwrap(); // This will purge the stream key records
        subject_addr.try_send(second_expired_cores_package).unwrap(); // This will be discarded

        System::current().stop();
        system.run();
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let transmit_data_msg = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(transmit_data_msg.endpoint, Endpoint::Socket(socket_addr));
        assert_eq!(transmit_data_msg.last_data, true);
        assert_eq!(transmit_data_msg.data, b"16 bytes of data".to_vec());
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(&format!(
            "DEBUG: {test_name}: Retiring stream key {:?} due to last data received from the exit node",
            stream_key
        ));
        tlh.exists_log_containing(&format!(
            "ERROR: {test_name}: Can't pay for return services consumed: received response with unrecognized stream key {:?}. Ignoring",
            stream_key
        ));
    }

    #[test]
    #[should_panic(expected = "time calculation error")]
    fn log_straggling_packet_panics_if_timestamp_is_wrong() {
        let subject = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        let stream_key = StreamKey::make_meaningless_stream_key();
        let timestamp = SystemTime::now()
            .checked_add(Duration::from_secs(10))
            .unwrap();
        let _ = subject.log_straggling_packet(&stream_key, 10, &timestamp);
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
            false,
        );
        subject.subs = Some(make_proxy_server_out_subs());

        let stream_key = StreamKey::make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(vec![], vec![]),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .tunneled_host("hostname")
                .build(),
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
                return_route_with_id(cryptde, 0),
                client_response_payload.into(),
                0,
            );

        subject.handle_client_response_payload(expired_cores_package);

        assert!(subject.keys_and_addrs.is_empty());
        assert!(subject.stream_info.get(&stream_key).is_none());
    }

    #[test]
    fn proxy_server_schedules_stream_key_purge_once_shutdown_order_is_received_for_stream() {
        let common_msg = StreamShutdownMsg {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                reception_port: 0,
                sequence_number: 0,
            }),
            report_to_counterpart: true,
        };
        assert_stream_is_purged_with_a_delay(StreamShutdownMsg {
            report_to_counterpart: true,
            ..common_msg.clone()
        });
        assert_stream_is_purged_with_a_delay(StreamShutdownMsg {
            report_to_counterpart: false,
            ..common_msg
        });
    }

    fn assert_stream_is_purged_with_a_delay(msg: StreamShutdownMsg) {
        /*
        +------------------------------------------------------------------+
        | (0ms)                                                            |
        | Stream shutdown is ordered                                       |
        +------------------------------------------------------------------+
                      |
                      v
        +------------------------------------------------------------------+
        | (400ms) (stream_key_purge_delay_in_millis - offset_in_millis)    |
        | Pre-purge assertion message finds records                        |
        +------------------------------------------------------------------+
                      |
                      v
        +------------------------------------------------------------------+
        | (500ms) (stream_key_purge_delay_in_millis)                       |
        | Stream is purged                                                 |
        +------------------------------------------------------------------+
                      |
                      v
        +------------------------------------------------------------------+
        | (600ms) (stream_key_purge_delay_in_millis + offset_in_millis)    |
        | Post-purge assertion message finds no records                    |
        +------------------------------------------------------------------+
        */

        init_test_logging();
        let test_name =
            "proxy_server_schedules_stream_key_purge_once_shutdown_order_is_received_for_stream";
        let cryptde = main_cryptde();
        let stream_key_purge_delay_in_millis = 500;
        let offset_in_millis = 100;
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        subject.stream_key_purge_delay = Duration::from_millis(stream_key_purge_delay_in_millis);
        subject.logger = Logger::new(&test_name);
        subject.subs = Some(make_proxy_server_out_subs());
        let stream_key = StreamKey::make_meaningful_stream_key(&test_name);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), msg.peer_addr.clone());
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(vec![], vec![]),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .tunneled_host("hostname")
                .build(),
        );
        let proxy_server_addr = subject.start();
        let schedule_stream_key_purge_sub = proxy_server_addr.clone().recipient();
        let mut peer_actors = peer_actors_builder().build();
        peer_actors.proxy_server.schedule_stream_key_purge = schedule_stream_key_purge_sub;
        let system = System::new(test_name);
        let bind_msg = BindMessage { peer_actors };
        proxy_server_addr.try_send(bind_msg).unwrap();
        let time_before_sending_package = SystemTime::now();

        proxy_server_addr.try_send(msg).unwrap();

        let time_after_sending_package = time_before_sending_package
            .checked_add(Duration::from_secs(1))
            .unwrap();
        let pre_purge_assertions = AssertionsMessage {
            assertions: Box::new(move |proxy_server: &mut ProxyServer| {
                let stream_info = proxy_server.stream_info.get(&stream_key).unwrap();
                let purge_timestamp = stream_info.time_to_live_opt.unwrap();
                assert!(
                    time_before_sending_package <= purge_timestamp
                        && purge_timestamp <= time_after_sending_package
                );
                assert!(!proxy_server.stream_info.get(&stream_key).is_none());
                assert!(!proxy_server.keys_and_addrs.is_empty());
                TestLogHandler::new().exists_log_containing(&format!(
                    "DEBUG: {test_name}: Client closed stream referenced by stream key {:?}, \
                    which was tunneling to the host \"hostname\". \
                    It will be purged after {stream_key_purge_delay_in_millis}ms.",
                    stream_key
                ));
            }),
        };
        proxy_server_addr
            .try_send(MessageScheduler {
                scheduled_msg: pre_purge_assertions,
                delay: Duration::from_millis(stream_key_purge_delay_in_millis - offset_in_millis), // 400ms
            })
            .unwrap();
        let post_purge_assertions = AssertionsMessage {
            assertions: Box::new(move |proxy_server: &mut ProxyServer| {
                assert!(proxy_server.keys_and_addrs.is_empty());
                assert!(proxy_server.stream_info.get(&stream_key).is_none());
                TestLogHandler::new().exists_log_containing(&format!(
                    "DEBUG: {test_name}: Retiring stream key {:?}",
                    stream_key
                ));
                System::current().stop();
            }),
        };
        proxy_server_addr
            .try_send(MessageScheduler {
                scheduled_msg: post_purge_assertions,
                delay: Duration::from_millis(stream_key_purge_delay_in_millis + offset_in_millis), // 600ms
            })
            .unwrap();
        system.run();
    }

    #[test]
    fn straggling_packets_are_charged_and_dropped_as_the_browser_stopped_awaiting_them_anyway() {
        init_test_logging();
        let test_name = "straggling_packets_are_charged_and_dropped_as_the_browser_stopped_awaiting_them_anyway";
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        subject.logger = Logger::new(test_name);
        subject.subs = Some(make_proxy_server_out_subs());
        let stream_key = StreamKey::make_meaningful_stream_key(test_name);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let exit_key = PublicKey::new(&b"blah"[..]);
        let exit_wallet = make_wallet("abc");
        let exit_rates = RatePack {
            routing_byte_rate: 0,
            routing_service_rate: 0,
            exit_byte_rate: 100,
            exit_service_rate: 60000,
        };
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![ExpectedService::Exit(
                            exit_key,
                            exit_wallet.clone(),
                            exit_rates.clone(),
                        )],
                    ),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .tunneled_host("hostname")
                .protocol(ProxyProtocol::HTTP)
                .time_to_live(SystemTime::now())
                .build(),
        );
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let (dispatcher, _, dispatcher_recording_arc) = make_recorder();
        let proxy_server_addr = subject.start();
        let peer_actors = peer_actors_builder()
            .accountant(accountant)
            .dispatcher(dispatcher)
            .build();
        let system = System::new(test_name);
        let response_data = vec![0; 30];
        let client_response_payload = ClientResponsePayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket::new(response_data.clone(), 1, true),
        };
        let expired_cores_package: ExpiredCoresPackage<ClientResponsePayload_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 0),
                client_response_payload.into(),
                5432,
            );
        let bind_msg = BindMessage { peer_actors };
        proxy_server_addr.try_send(bind_msg).unwrap();

        proxy_server_addr.try_send(expired_cores_package).unwrap();

        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let msg = accountant_recording.get_record::<ReportServicesConsumedMessage>(0);
        assert_eq!(
            &msg.exit,
            &ExitServiceConsumed {
                earning_wallet: exit_wallet,
                payload_size: response_data.len(),
                service_rate: exit_rates.exit_service_rate,
                byte_rate: exit_rates.exit_byte_rate,
            }
        );
        assert_eq!(msg.routing_payload_size, 5432);
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let len = dispatcher_recording.len();
        assert_eq!(len, 0);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Straggling packet of length 5432 received for a \
            stream key {:?} after a delay of",
            stream_key
        ));
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
            false,
        );
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
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
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![
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
                    ),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .build(),
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
                return_route_with_id(cryptde, 0),
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
        let peer_actors = peer_actors_builder()
            .dispatcher(dispatcher_mock)
            .accountant(accountant)
            .build();
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
                    earning_wallet: incoming_route_d_wallet.clone(),
                    payload_size: first_exit_size,
                    service_rate: rate_pack_d.exit_service_rate,
                    byte_rate: rate_pack_d.exit_byte_rate
                },
                routing_payload_size: routing_size,
                routing: vec![
                    RoutingServiceConsumed {
                        earning_wallet: incoming_route_e_wallet.clone(),
                        service_rate: rate_pack_e.routing_service_rate,
                        byte_rate: rate_pack_e.routing_byte_rate
                    },
                    RoutingServiceConsumed {
                        earning_wallet: incoming_route_f_wallet.clone(),
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
                    earning_wallet: incoming_route_d_wallet,
                    payload_size: second_exit_size,
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
        assert!(before <= second_report_timestamp && second_report_timestamp <= after);
        assert_eq!(accountant_recording.len(), 2);
    }

    #[test]
    fn dns_retry_entry_is_removed_after_a_successful_client_response() {
        init_test_logging();
        let test_name = "dns_retry_entry_is_removed_after_a_successful_client_response";
        let system = System::new(test_name);
        let cryptde = main_cryptde();
        let logger = Logger::new(test_name);
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let stream_key_clone = stream_key.clone();
        let irrelevant_public_key = PublicKey::from(&b"irrelevant"[..]);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.logger = Logger::new(test_name);
        let mut dns_fail_client_payload = make_request_payload(111, cryptde);
        dns_fail_client_payload.stream_key = stream_key;
        let incoming_route_d_wallet = make_wallet("D Earning");
        let incoming_route_e_wallet = make_wallet("E Earning");
        let incoming_route_f_wallet = make_wallet("F Earning");
        let rate_pack_d = rate_pack(101);
        let rate_pack_e = rate_pack(102);
        let rate_pack_f = rate_pack(103);
        subject.stream_info.insert(
            stream_key_clone.clone(),
            StreamInfoBuilder::new()
                .dns_failure_retry(DNSFailureRetry {
                    unsuccessful_request: dns_fail_client_payload,
                    retries_left: 3,
                })
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![
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
                    ),
                    host: Host::new("booga.com", TLS_PORT),
                })
                .protocol(ProxyProtocol::TLS)
                .build(),
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
        let first_expired_cores_package: ExpiredCoresPackage<ClientResponsePayload_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 0),
                first_client_response_payload.into(),
                0,
            );
        let peer_actors = peer_actors_builder().build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(first_expired_cores_package).unwrap();

        subject_addr
            .try_send(AssertionsMessage {
                assertions: Box::new(move |proxy_server: &mut ProxyServer| {
                    let retry_opt = &proxy_server
                        .stream_info(&stream_key_clone, &logger)
                        .unwrap()
                        .dns_failure_retry_opt;
                    assert!(retry_opt.is_none());
                }),
            })
            .unwrap();
        System::current().stop();
        system.run();
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
            false,
        );
        let stream_key = StreamKey::make_meaningless_stream_key();
        let irrelevant_public_key = PublicKey::from(&b"irrelevant"[..]);
        // subject.keys_and_addrs contains no browser stream
        let incoming_route_d_wallet = make_wallet("D Earning");
        let incoming_route_e_wallet = make_wallet("E Earning");
        let rate_pack_d = rate_pack(101);
        let rate_pack_e = rate_pack(102);
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![
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
                    ),
                    host: Host::new("booga.com", TLS_PORT),
                })
                .protocol(ProxyProtocol::TLS)
                .build(),
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
                return_route_with_id(cryptde, 0),
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
            false,
        );

        let stream_key = StreamKey::make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_payload = make_request_payload(111, cryptde);
        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .dns_failure_retry(DNSFailureRetry {
                    unsuccessful_request: client_payload,
                    retries_left: 0,
                })
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![ExpectedService::Exit(
                            exit_public_key.clone(),
                            exit_wallet,
                            rate_pack(10),
                        )],
                    ),
                    host: Host::new("server.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .build(),
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 0),
                dns_resolve_failure.into(),
                0,
            );

        let peer_actors = peer_actors_builder().dispatcher(dispatcher_mock).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
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
                data: ServerImpersonatorHttp {}
                    .dns_resolution_failure_response("server.com".to_string()),
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
            false,
        );
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let irrelevant_public_key = PublicKey::from(&b"irrelevant"[..]);
        let client_payload = make_request_payload(111, cryptde);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let incoming_route_d_wallet = make_wallet("D Earning");
        let incoming_route_e_wallet = make_wallet("E Earning");
        let incoming_route_f_wallet = make_wallet("F Earning");
        let rate_pack_d = rate_pack(101);
        let rate_pack_e = rate_pack(102);
        let rate_pack_f = rate_pack(103);
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .dns_failure_retry(DNSFailureRetry {
                    unsuccessful_request: client_payload,
                    retries_left: 0,
                })
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![
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
                    ),
                    host: Host::new("booga.com", TLS_PORT),
                })
                .protocol(ProxyProtocol::TLS)
                .build(),
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure_payload = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 0),
                dns_resolve_failure_payload.into(),
                0,
            );
        let routing_size = expired_cores_package.payload_len;
        let peer_actors = peer_actors_builder().accountant(accountant).build();
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
        init_test_logging();
        let test_name = "handle_dns_resolve_failure_sends_message_to_neighborhood";
        let system = System::new(test_name);
        let (neighborhood_mock, _, neighborhood_log_arc) = make_recorder();
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        let stream_key = StreamKey::make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_payload = make_request_payload(111, cryptde);
        subject.logger = Logger::new(test_name);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .dns_failure_retry(DNSFailureRetry {
                    unsuccessful_request: client_payload,
                    retries_left: 0,
                })
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![ExpectedService::Exit(
                            exit_public_key.clone(),
                            exit_wallet.clone(),
                            rate_pack(10),
                        )],
                    ),
                    host: Host::new("server.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .build(),
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 0),
                dns_resolve_failure.into(),
                0,
            );
        let peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .build();

        subject_addr.try_send(BindMessage { peer_actors }).unwrap();
        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop();
        system.run();
        let neighborhood_recording = neighborhood_log_arc.lock().unwrap();
        let record = neighborhood_recording.get_record::<UpdateNodeRecordMetadataMessage>(0);
        assert_eq!(
            record,
            &UpdateNodeRecordMetadataMessage {
                public_key: exit_public_key.clone(),
                metadata_change: NRMetadataChange::AddUnreachableHost {
                    hostname: "server.com".to_string()
                }
            }
        );
        TestLogHandler::new().exists_no_log_containing(&format!(
            "ERROR: {test_name}: Exit node {exit_public_key} complained of DNS failure, but was given no hostname to resolve."
        ));
    }

    #[test]
    fn handle_dns_resolve_failure_logs_when_stream_key_is_found_in_stream_info_but_not_keys_and_addrs(
    ) {
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
            false,
        );
        let stream_key = StreamKey::make_meaningless_stream_key();
        let return_route_id = 0;
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_payload = make_request_payload(111, cryptde);
        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        subject.stream_info.insert(
            stream_key,
            StreamInfoBuilder::new()
                .dns_failure_retry(DNSFailureRetry {
                    unsuccessful_request: client_payload,
                    retries_left: 0,
                })
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![ExpectedService::Exit(
                            exit_public_key.clone(),
                            exit_wallet.clone(),
                            rate_pack(10),
                        )],
                    ),
                    host: Host::new("server.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .build(),
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
            ExpiredCoresPackage::new(
                socket_addr,
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, return_route_id),
                dns_resolve_failure.into(),
                0,
            );
        let already_used_expired_cores_package = expired_cores_package.clone();
        let peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .build();
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
            false,
        );
        let stream_key = StreamKey::make_meaningless_stream_key();
        let return_route_id = 0;
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_payload = make_request_payload(111, cryptde);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        subject.stream_info.insert(
            stream_key,
            StreamInfoBuilder::new()
                .dns_failure_retry(DNSFailureRetry {
                    unsuccessful_request: client_payload,
                    retries_left: 0,
                })
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![ExpectedService::Exit(
                            exit_public_key.clone(),
                            exit_wallet.clone(),
                            rate_pack(10),
                        )],
                    ),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .build(),
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
        let peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();
        subject_addr
            .try_send(already_used_expired_cores_package)
            .unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(&format!(
            "Discarding DnsResolveFailure message from an unrecognized stream key {:?}",
            stream_key
        ));
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
        let stream_key = StreamKey::make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_payload = make_request_payload(111, cryptde);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.stream_info.insert(
            stream_key,
            StreamInfoBuilder::new()
                .dns_failure_retry(DNSFailureRetry {
                    unsuccessful_request: client_payload,
                    retries_left: 0,
                })
                .tunneled_host("tunneled host")
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![
                            make_exit_service_from_key(PublicKey::new(b"exit_node")),
                            ExpectedService::Nothing,
                        ],
                    ),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .build(),
        );
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 0),
                dns_resolve_failure.into(),
                0,
            );

        subject.handle_dns_resolve_failure(&expired_cores_package);

        assert!(subject.keys_and_addrs.is_empty());
        assert!(subject.stream_info.get(&stream_key).is_none());
    }

    #[test]
    fn handle_dns_resolve_failure_zero_hop() {
        let system = System::new("handle_dns_resolve_failure_zero_hop");
        let (dispatcher_mock, _, dispatcher_recording_arc) = make_recorder();
        let (neighborhood_mock, _, neighborhood_recording_arc) = make_recorder();
        let cryptde = main_cryptde();
        let this_node_public_key = cryptde.public_key();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            false, //meaning ZeroHop
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        let stream_key = StreamKey::make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_payload = make_request_payload(111, cryptde);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .dns_failure_retry(DNSFailureRetry {
                    unsuccessful_request: client_payload,
                    retries_left: 0,
                })
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![ExpectedService::Nothing, ExpectedService::Nothing],
                    ),
                    host: Host::new("server.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .build(),
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 0),
                dns_resolve_failure.into(),
                0,
            );
        let peer_actors = peer_actors_builder()
            .dispatcher(dispatcher_mock)
            .neighborhood(neighborhood_mock)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop();
        system.run();
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        let msg = neighborhood_recording.get_record::<UpdateNodeRecordMetadataMessage>(0);
        assert_eq!(
            msg,
            &UpdateNodeRecordMetadataMessage {
                public_key: this_node_public_key.clone(),
                metadata_change: NRMetadataChange::AddUnreachableHost {
                    hostname: "server.com".to_string()
                }
            }
        );
        let dispatcher_recording = dispatcher_recording_arc.lock().unwrap();
        let record = dispatcher_recording.get_record::<TransmitDataMsg>(0);
        assert_eq!(
            TransmitDataMsg {
                endpoint: Endpoint::Socket(socket_addr),
                last_data: true,
                sequence_number: Some(0),
                data: ServerImpersonatorHttp {}
                    .dns_resolution_failure_response("server.com".to_string()),
            },
            *record
        );
    }

    #[test]
    fn handle_dns_resolve_failure_sent_request_retry() {
        let test_name = "handle_dns_resolve_failure_sent_request_retry";
        let system = System::new(test_name);
        let logger = Logger::new(test_name);
        let resolve_message_params_arc = Arc::new(Mutex::new(vec![]));
        let (neighborhood_mock, _, _) = make_recorder();
        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        let expected_services = vec![ExpectedService::Exit(
            exit_public_key.clone(),
            exit_wallet,
            rate_pack(10),
        )];
        let route_query_response_expected = RouteQueryResponse {
            route: make_meaningless_route(),
            expected_services: ExpectedServices::RoundTrip(
                expected_services.clone(),
                expected_services.clone(),
            ),
            host: Host::new("booga.com", HTTP_PORT),
        };
        let neighborhood_mock = neighborhood_mock
            .system_stop_conditions(match_every_type_id!(RouteQueryMessage))
            .route_query_response(Some(route_query_response_expected.clone()));
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_payload = make_request_payload(111, cryptde);
        let stream_key = client_payload.stream_key;
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .dns_failure_retry(DNSFailureRetry {
                    unsuccessful_request: client_payload.clone(),
                    retries_left: 3,
                })
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        expected_services.clone(),
                    ),
                    host: Host::new("server.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .build(),
        );
        let message_resolver = RouteQueryResponseResolverMock::default()
            .resolve_message_params(&resolve_message_params_arc);
        let message_resolver_factory = RouteQueryResponseResolverFactoryMock::default()
            .make_result(Box::new(message_resolver));
        subject.inbound_client_data_helper_opt = Some(Box::new(IBCDHelperReal {
            factory: Box::new(message_resolver_factory),
        }));
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 0),
                dns_resolve_failure.into(),
                0,
            );
        let peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        subject_addr
            .try_send(AssertionsMessage {
                assertions: Box::new(move |proxy_server: &mut ProxyServer| {
                    let retry = proxy_server
                        .stream_info(&stream_key, &logger)
                        .unwrap()
                        .dns_failure_retry_opt
                        .as_ref()
                        .unwrap();
                    assert_eq!(retry.retries_left, 2);
                }),
            })
            .unwrap();
        let before = SystemTime::now();
        system.run();
        let after = SystemTime::now();
        let mut resolve_message_params = resolve_message_params_arc.lock().unwrap();
        let (transmit_to_hopper_args, route_query_message_response) =
            resolve_message_params.remove(0);
        let args = transmit_to_hopper_args;
        assert!(resolve_message_params.is_empty());
        assert_eq!(args.payload, client_payload);
        assert_eq!(args.client_addr, socket_addr);
        assert!(before <= args.timestamp && args.timestamp <= after);
        assert!(args.retire_stream_key_sub_opt.is_none());
        assert_eq!(args.is_decentralized, true);
        assert_eq!(
            route_query_message_response.unwrap().unwrap(),
            route_query_response_expected
        );
    }

    #[test]
    fn handle_dns_resolve_failure_logs_error_when_there_is_no_dns_failure_retry_entry_for_the_stream_key(
    ) {
        init_test_logging();
        let test_name = "handle_dns_resolve_failure_logs_error_when_there_is_no_dns_failure_retry_entry_for_the_stream_key";
        let system = System::new(test_name);
        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        let expected_services = vec![ExpectedService::Exit(
            exit_public_key.clone(),
            exit_wallet,
            rate_pack(10),
        )];
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        let stream_key = StreamKey::make_meaningless_stream_key();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        subject.logger = Logger::new(test_name);
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        expected_services.clone(),
                    ),
                    host: Host::new("server.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .build(),
        );
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 0),
                dns_resolve_failure.into(),
                0,
            );
        let peer_actors = peer_actors_builder().build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: {test_name}: While \
        handling ExpiredCoresPackage: No DNSFailureRetry entry found for the stream_key: {stream_key}"
        ));
    }

    #[test]
    fn handle_dns_resolve_failure_sent_request_retry_three_times() {
        init_test_logging();
        let test_name = "handle_dns_resolve_failure_sent_request_retry_three_times";
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let system = System::new(test_name);
        let (neighborhood_mock, _, _) = make_recorder();
        let exit_public_key = PublicKey::from(&b"exit_key"[..]);
        let exit_wallet = make_wallet("exit wallet");
        let expected_services = vec![ExpectedService::Exit(
            exit_public_key.clone(),
            exit_wallet,
            rate_pack(10),
        )];
        let route_query_response_expected = RouteQueryResponse {
            route: make_meaningless_route(),
            expected_services: ExpectedServices::RoundTrip(
                expected_services.clone(),
                expected_services.clone(),
            ),
            host: Host::new("booga.com", HTTP_PORT),
        };
        let neighborhood_mock = neighborhood_mock
            .system_stop_conditions(match_every_type_id!(
                RouteQueryMessage,
                RouteQueryMessage,
                RouteQueryMessage
            ))
            .route_query_response(Some(route_query_response_expected.clone()));
        let cryptde = main_cryptde();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        subject.logger = Logger::new(test_name);
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let client_payload = make_request_payload(111, cryptde);
        let stream_key = client_payload.stream_key;
        let stream_key_clone = stream_key.clone();
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        subject.stream_info.insert(
            stream_key_clone.clone(),
            StreamInfoBuilder::new()
                .dns_failure_retry(DNSFailureRetry {
                    unsuccessful_request: client_payload,
                    retries_left: 3,
                })
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        expected_services.clone(),
                    ),
                    host: Host::new("server.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .build(),
        );
        let message_resolver_factory = RouteQueryResponseResolverFactoryMock::default()
            .make_params(&make_params_arc)
            .make_result(Box::new(RouteQueryResponseResolverMock::default()))
            .make_result(Box::new(RouteQueryResponseResolverMock::default()))
            .make_result(Box::new(RouteQueryResponseResolverMock::default()))
            .make_result(Box::new(RouteQueryResponseResolverMock::default()));
        subject.inbound_client_data_helper_opt = Some(Box::new(IBCDHelperReal {
            factory: Box::new(message_resolver_factory),
        }));
        let subject_addr: Addr<ProxyServer> = subject.start();
        let dns_resolve_failure = DnsResolveFailure_0v1::new(stream_key);
        let expired_cores_package: ExpiredCoresPackage<DnsResolveFailure_0v1> =
            ExpiredCoresPackage::new(
                SocketAddr::from_str("1.2.3.4:1234").unwrap(),
                Some(make_wallet("irrelevant")),
                return_route_with_id(cryptde, 0),
                dns_resolve_failure.into(),
                0,
            );
        let peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr
            .try_send(expired_cores_package.clone())
            .unwrap();
        subject_addr
            .try_send(expired_cores_package.clone())
            .unwrap();
        subject_addr
            .try_send(expired_cores_package.clone())
            .unwrap();
        subject_addr.try_send(expired_cores_package).unwrap();

        subject_addr
            .try_send(AssertionsMessage {
                assertions: Box::new(move |proxy_server: &mut ProxyServer| {
                    assert_eq!(proxy_server.keys_and_addrs.a_to_b(&stream_key), None);
                    assert_eq!(proxy_server.stream_info.get(&stream_key).is_none(), true);
                }),
            })
            .unwrap();
        system.run();
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(make_params.len(), 3);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Retiring stream key {stream_key_clone} due to DNS resolution failure"
        ));
    }

    #[test]
    #[should_panic(expected = "Dispatcher unbound in ProxyServer")]
    fn panics_if_dispatcher_is_unbound() {
        let system = System::new("panics_if_dispatcher_is_unbound");
        let cryptde = main_cryptde();
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let mut subject = ProxyServer::new(
            cryptde,
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        subject
            .keys_and_addrs
            .insert(stream_key.clone(), socket_addr.clone());
        let remaining_route = return_route_with_id(cryptde, 4321);
        subject.stream_info.insert(
            stream_key.clone(),
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(
                        vec![],
                        vec![ExpectedService::Nothing],
                    ),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .protocol(ProxyProtocol::HTTP)
                .build(),
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
            false,
        );
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(80),
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
            false,
        );
        let stream_key = StreamKey::make_meaningless_stream_key();
        subject
            .keys_and_addrs
            .insert(stream_key, SocketAddr::from_str("1.2.3.4:5678").unwrap());
        let subject_addr: Addr<ProxyServer> = subject.start();
        let peer_actors = peer_actors_builder()
            .dispatcher(dispatcher)
            .accountant(accountant)
            .build();
        let client_response_payload = ClientResponsePayload_0v1 {
            stream_key: stream_key.clone(),
            sequenced_packet: SequencedPacket {
                data: b"some data".to_vec(),
                sequence_number: 4321,
                last_data: false,
            },
        };
        let expired_cores_package = ExpiredCoresPackage::new(
            SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            Some(make_wallet("irrelevant")),
            return_route_with_id(cryptde, 0 /* dummy */),
            client_response_payload,
            0,
        );
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(expired_cores_package).unwrap();

        System::current().stop();
        system.run();
        TestLogHandler::new().exists_log_containing(format!("ERROR: ProxyServer: Can't pay for return services consumed: received response with unrecognized stream key {}. Ignoring", stream_key).as_str());
        assert_eq!(dispatcher_recording_arc.lock().unwrap().len(), 0);
        assert_eq!(accountant_recording_arc.lock().unwrap().len(), 0);
    }

    #[test]
    fn handle_stream_shutdown_msg_handles_unknown_peer_addr() {
        let test_name = "handle_stream_shutdown_msg_handles_unknown_peer_addr";
        let logger = Logger::new(test_name);
        let mut subject =
            ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, false, false);
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key = StreamKey::make_meaningful_stream_key("unaffected");
        subject
            .keys_and_addrs
            .insert(unaffected_stream_key, unaffected_socket_addr);
        subject.stream_info.insert(
            unaffected_stream_key,
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(vec![], vec![]),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .tunneled_host("blah")
                .build(),
        );

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
        assert!(subject.stream_info.contains_key(&unaffected_stream_key));
        assert!(subject
            .stream_info(&unaffected_stream_key, &logger)
            .unwrap()
            .tunneled_host_opt
            .is_some());
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
            false,
        );
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key = StreamKey::make_meaningful_stream_key("unaffected");
        let affected_socket_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();
        let affected_stream_key = StreamKey::make_meaningful_stream_key("affected");
        let affected_cryptde = CryptDENull::from(&PublicKey::new(b"affected"), TEST_DEFAULT_CHAIN);
        subject
            .keys_and_addrs
            .insert(unaffected_stream_key, unaffected_socket_addr);
        subject
            .keys_and_addrs
            .insert(affected_stream_key, affected_socket_addr);
        subject.stream_info.insert(
            unaffected_stream_key,
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(vec![], vec![]),
                    host: Host::new("gooba.com", HTTP_PORT),
                })
                .tunneled_host("blah")
                .build(),
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
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();
        let affected_expected_services = vec![ExpectedService::Exit(
            affected_cryptde.public_key().clone(),
            make_paying_wallet(b"1234"),
            DEFAULT_RATE_PACK,
        )];
        subject.stream_info.insert(
            affected_stream_key,
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: affected_route.clone(),
                    expected_services: ExpectedServices::RoundTrip(
                        affected_expected_services,
                        vec![],
                    ),
                    host: Host::new("gooba.com", TLS_PORT),
                })
                .tunneled_host("tunneled.com")
                .build(),
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
        assert_eq!(
            record.route,
            affected_route
        );
        let payload = decodex::<MessageType>(&affected_cryptde, &record.payload).unwrap();
        match payload {
            MessageType::ClientRequest(vd) => assert_eq!(
                vd.extract(&crate::sub_lib::migrations::client_request_payload::MIGRATIONS)
                    .unwrap(),
                ClientRequestPayload_0v1 {
                    stream_key: affected_stream_key,
                    sequenced_packet: SequencedPacket::new(vec![], 1234, true),
                    target_hostname: String::from("tunneled.com"),
                    target_port: TLS_PORT,
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
        init_test_logging();
        let test_name =
            "handle_stream_shutdown_msg_reports_to_counterpart_without_tunnel_when_necessary";
        let system = System::new(test_name);
        let mut subject = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        let unaffected_socket_addr = SocketAddr::from_str("2.3.4.5:6789").unwrap();
        let unaffected_stream_key = StreamKey::make_meaningful_stream_key("unaffected");
        let affected_socket_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();
        let affected_stream_key = StreamKey::make_meaningful_stream_key("affected");
        let affected_cryptde = CryptDENull::from(&PublicKey::new(b"affected"), TEST_DEFAULT_CHAIN);
        subject
            .keys_and_addrs
            .insert(unaffected_stream_key, unaffected_socket_addr);
        subject
            .keys_and_addrs
            .insert(affected_stream_key, affected_socket_addr);
        subject.stream_info.insert(
            unaffected_stream_key,
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(vec![], vec![]),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .build(),
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
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();
        let affected_expected_services = vec![ExpectedService::Exit(
            affected_cryptde.public_key().clone(),
            make_paying_wallet(b"1234"),
            DEFAULT_RATE_PACK,
        )];
        subject.stream_info.insert(
            affected_stream_key,
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: affected_route.clone(),
                    expected_services: ExpectedServices::RoundTrip(
                        affected_expected_services,
                        vec![],
                    ),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .build(),
        );
        subject.logger = Logger::new(test_name);
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
        assert_eq!(
            record.route,
            affected_route
        );
        let payload = decodex::<MessageType>(&affected_cryptde, &record.payload).unwrap();
        match payload {
            MessageType::ClientRequest(vd) => assert_eq!(
                vd.extract(&crate::sub_lib::migrations::client_request_payload::MIGRATIONS)
                    .unwrap(),
                ClientRequestPayload_0v1 {
                    stream_key: affected_stream_key,
                    sequenced_packet: SequencedPacket::new(vec![], 1234, true),
                    target_hostname: "booga.com".to_string(),
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
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Client closed stream referenced by stream key {:?}. \
            It will be purged after {:?}.",
            &affected_stream_key, STREAM_KEY_PURGE_DELAY
        ));
    }

    #[test]
    fn handle_stream_shutdown_msg_logs_errors_from_handling_normal_client_data() {
        init_test_logging();
        let mut subject =
            ProxyServer::new(main_cryptde(), alias_cryptde(), true, Some(0), false, false);
        subject.subs = Some(make_proxy_server_out_subs());
        let helper = IBCDHelperMock::default()
            .handle_normal_client_data_result(Err("Our help is not welcome".to_string()));
        subject.inbound_client_data_helper_opt = Some(Box::new(helper));
        let socket_addr = SocketAddr::from_str("3.4.5.6:7777").unwrap();
        let stream_key = StreamKey::make_meaningful_stream_key("All Things Must Pass");
        subject.keys_and_addrs.insert(stream_key, socket_addr);
        subject
            .stream_info
            .insert(stream_key.clone(), StreamInfoBuilder::new().build());
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
        let mut subject =
            ProxyServer::new(main_cryptde(), alias_cryptde(), true, Some(0), false, false);
        subject.subs = Some(make_proxy_server_out_subs());
        let icd_helper = IBCDHelperMock::default()
            .handle_normal_client_data_params(&help_to_handle_normal_client_data_params_arc)
            .handle_normal_client_data_result(Ok(()));
        subject.inbound_client_data_helper_opt = Some(Box::new(icd_helper));
        let socket_addr = SocketAddr::from_str("3.4.5.6:7890").unwrap();
        let stream_key = StreamKey::make_meaningful_stream_key("All Things Must Pass");
        subject.keys_and_addrs.insert(stream_key, socket_addr);
        subject.stream_info.insert(
            stream_key,
            StreamInfoBuilder::new()
                .route(RouteQueryResponse {
                    route: Route { hops: vec![] },
                    expected_services: ExpectedServices::RoundTrip(vec![], vec![]),
                    host: Host::new("booga.com", HTTP_PORT),
                })
                .tunneled_host("blah")
                .build(),
        );
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
        assert_eq!(inbound_client_data_msg.client_addr, socket_addr);
        assert_eq!(inbound_client_data_msg.data, Vec::<u8>::new());
        assert_eq!(inbound_client_data_msg.last_data, true);
        assert_eq!(inbound_client_data_msg.is_clandestine, false);
        let actual_timestamp = inbound_client_data_msg.timestamp;
        assert!(before <= actual_timestamp && actual_timestamp <= after);
        assert_eq!(*retire_stream_key, true)
    }

    #[test]
    fn help_to_handle_normal_client_data_missing_consuming_wallet_and_protocol_pack_not_found() {
        let mut proxy_server =
            ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, false, false);
        proxy_server.subs = Some(make_proxy_server_out_subs());
        let inbound_client_data_msg = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:4578").unwrap(),
            reception_port_opt: None,
            last_data: true,
            is_clandestine: false,
            sequence_number: Some(123),
            data: vec![],
        };

        let result = IBCDHelperReal::new().handle_normal_client_data(
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
    fn resolve_message_handles_mailbox_error_from_neighborhood() {
        let cryptde = main_cryptde();
        let payload = make_request_payload(111, cryptde);
        let stream_key = payload.stream_key;
        let (proxy_server, _, proxy_server_recording_arc) = make_recorder();
        let addr = proxy_server.start();
        let proxy_server_sub = recipient!(&addr, AddRouteResultMessage);
        let args = TransmitToHopperArgs {
            main_cryptde: cryptde,
            payload,
            client_addr: SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            timestamp: SystemTime::now(),
            is_decentralized: false,
            logger: Logger::new("test"),
            hopper_sub: recipient!(&addr, IncipientCoresPackage),
            dispatcher_sub: recipient!(&addr, TransmitDataMsg),
            accountant_sub: recipient!(&addr, ReportServicesConsumedMessage),
            retire_stream_key_sub_opt: None,
        };
        let subject = RouteQueryResponseResolverReal {};
        let system = System::new("resolve_message_handles_mailbox_error_from_neighborhood");

        subject.resolve_message(args, proxy_server_sub, Err(MailboxError::Timeout));

        System::current().stop();
        system.run();
        let proxy_server_recording = proxy_server_recording_arc.lock().unwrap();
        let message = proxy_server_recording.get_record::<AddRouteResultMessage>(0);
        let expected_error_message = "Neighborhood refused to answer route request: MailboxError(Message delivery timed out)";
        assert_eq!(
            message,
            &AddRouteResultMessage {
                stream_key,
                result: Err(expected_error_message.to_string())
            }
        );
    }

    #[derive(Default)]
    struct ClientRequestPayloadFactoryMock {
        make_params: Arc<Mutex<Vec<(InboundClientData, StreamKey, Option<Host>, Box<dyn CryptDE>, Logger)>>>,
        make_results: RefCell<Vec<Option<ClientRequestPayload_0v1>>>,
    }

    impl ClientRequestPayloadFactory for ClientRequestPayloadFactoryMock {
        fn make(
            &self,
            ibcd: &InboundClientData,
            stream_key: StreamKey,
            host_opt: Option<Host>,
            cryptde: &dyn CryptDE,
            logger: &Logger,
        ) -> Option<ClientRequestPayload_0v1> {
            self.make_params
                .lock()
                .unwrap()
                .push((ibcd.clone(), stream_key, host_opt, cryptde.dup(), logger.clone()));
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl ClientRequestPayloadFactoryMock {
        fn new() -> Self {
            Self::default()
        }

        fn make_params(mut self, params: &Arc<Mutex<Vec<(InboundClientData, StreamKey, Option<Host>, Box<dyn CryptDE>, Logger)>>>) -> Self {
            self.make_params = params.clone();
            self
        }

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
            false,
        );
        proxy_server.subs = Some(make_proxy_server_out_subs());
        proxy_server.client_request_payload_factory =
            Box::new(ClientRequestPayloadFactoryMock::default().make_result(None));
        let inbound_client_data_msg = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:4578").unwrap(),
            reception_port_opt: Some(568),
            last_data: true,
            is_clandestine: false,
            sequence_number: Some(123),
            data: vec![],
        };

        let result = IBCDHelperReal::new().handle_normal_client_data(
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
    fn new_http_request_creates_new_entry_inside_dns_retries_hashmap() {
        let test_name = "new_http_request_creates_new_entry_inside_dns_retries_hashmap";
        let logger = Logger::new(test_name);
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (neighborhood_mock, _, _) = make_recorder();
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
            ),
            host: Host::new("booga.com", HTTP_PORT),
        }));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_payload = ClientRequestPayloadFactoryReal::new()
            .make(
                &msg_from_dispatcher,
                stream_key.clone(),
                None,
                alias_cryptde,
                &Logger::new("test"),
            )
            .unwrap();
        let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key.clone());
        let system = System::new(
            "proxy_server_receives_http_request_from_dispatcher_then_sends_cores_package_to_hopper",
        );
        let mut subject = ProxyServer::new(
            main_cryptde,
            alias_cryptde,
            true,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        subject.stream_key_factory = Box::new(stream_key_factory);
        let subject_addr: Addr<ProxyServer> = subject.start();
        let peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(msg_from_dispatcher).unwrap();

        subject_addr
            .try_send(AssertionsMessage {
                assertions: Box::new(move |proxy_server: &mut ProxyServer| {
                    let dns_retry = proxy_server
                        .stream_info(&stream_key, &logger)
                        .unwrap()
                        .dns_failure_retry_opt
                        .as_ref()
                        .unwrap();
                    assert_eq!(dns_retry.retries_left, 3);
                    assert_eq!(dns_retry.unsuccessful_request, expected_payload);
                }),
            })
            .unwrap();
        System::current().stop();
        system.run();
    }

    #[test]
    fn new_http_request_creates_new_exhausted_entry_inside_dns_retries_hashmap_zero_hop() {
        let test_name =
            "new_http_request_creates_new_exhausted_entry_inside_dns_retries_hashmap_zero_hop";
        let logger = Logger::new(test_name);
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: nowhere.com\r\n\r\n";
        let (neighborhood_mock, _, _) = make_recorder();
        let destination_key = PublicKey::from(&b"our destination"[..]);
        let neighborhood_mock = neighborhood_mock.route_query_response(Some(RouteQueryResponse {
            route: Route { hops: vec![] },
            expected_services: ExpectedServices::RoundTrip(
                vec![make_exit_service_from_key(destination_key.clone())],
                vec![],
            ),
            host: Host::new("booga.com", HTTP_PORT),
        }));
        let socket_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let stream_key = StreamKey::make_meaningless_stream_key();
        let expected_data = http_request.to_vec();
        let msg_from_dispatcher = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr.clone(),
            reception_port_opt: Some(HTTP_PORT),
            sequence_number: Some(0),
            last_data: true,
            is_clandestine: false,
            data: expected_data.clone(),
        };
        let expected_payload = ClientRequestPayloadFactoryReal::new()
            .make(
                &msg_from_dispatcher,
                stream_key.clone(),
                None,
                alias_cryptde,
                &Logger::new("test"),
            )
            .unwrap();
        let stream_key_factory = StreamKeyFactoryMock::new().make_result(stream_key.clone());
        let system = System::new(
            "new_http_request_creates_new_exhausted_entry_inside_dns_retries_hashmap_zero_hop",
        );
        let mut subject = ProxyServer::new(
            main_cryptde,
            alias_cryptde,
            false,
            Some(STANDARD_CONSUMING_WALLET_BALANCE),
            false,
            false,
        );
        subject.stream_key_factory = Box::new(stream_key_factory);
        let subject_addr: Addr<ProxyServer> = subject.start();
        let peer_actors = peer_actors_builder()
            .neighborhood(neighborhood_mock)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(msg_from_dispatcher).unwrap();

        subject_addr
            .try_send(AssertionsMessage {
                assertions: Box::new(move |proxy_server: &mut ProxyServer| {
                    let dns_retry = proxy_server
                        .stream_info(&stream_key, &logger)
                        .unwrap()
                        .dns_failure_retry_opt
                        .as_ref()
                        .unwrap();
                    assert_eq!(dns_retry.retries_left, 0);
                    assert_eq!(dns_retry.unsuccessful_request, expected_payload);
                }),
            })
            .unwrap();
        System::current().stop();
        system.run();
    }

    #[test]
    fn hostname_works() {
        assert_on_hostname(
            "https://www.example.com/folder/file.html",
            "www.example.com",
        );
        assert_on_hostname("www.example.com/index.php?arg=test", "www.example.com");
        assert_on_hostname("sub.example.com/index.php?arg=test", "sub.example.com");
        assert_on_hostname("1.1.1.1", "1.1.1.1");
        assert_on_hostname("", "");
        assert_on_hostname("example", "example");
        assert_on_hostname(
            "htttttps://www.example.com/folder/file.html",
            "htttttps://www.example.com/folder/file.html",
        );
    }

    fn assert_on_hostname(raw_url: &str, expected_hostname: &str) {
        let clean_hostname = Hostname::new(raw_url);
        let expected_result = Hostname {
            hostname: expected_hostname.to_string(),
        };
        assert_eq!(expected_result, clean_hostname);
    }

    #[test]
    fn hostname_is_valid_works() {
        // IPv4
        assert_eq!(
            Hostname::new("0.0.0.0").validate_non_loopback_host(),
            Err("0.0.0.0".to_string())
        );
        assert_eq!(
            Hostname::new("192.168.1.158").validate_non_loopback_host(),
            Ok(())
        );
        // IPv6
        assert_eq!(
            Hostname::new("0:0:0:0:0:0:0:0").validate_non_loopback_host(),
            Err("::".to_string())
        );
        assert_eq!(
            Hostname::new("0:0:0:0:0:0:0:1").validate_non_loopback_host(),
            Err("::1".to_string())
        );
        assert_eq!(
            Hostname::new("2001:0db8:85a3:0000:0000:8a2e:0370:7334").validate_non_loopback_host(),
            Ok(())
        );
        // Hostname
        assert_eq!(
            Hostname::new("localhost").validate_non_loopback_host(),
            Err("localhost".to_string())
        );
        assert_eq!(
            Hostname::new("www.example.com").validate_non_loopback_host(),
            Ok(())
        );
        assert_eq!(
            Hostname::new("https://www.example.com").validate_non_loopback_host(),
            Ok(())
        );
    }

    #[test]
    fn proxy_server_field_test_is_running_in_integration_test() {
        let is_running_in_integration_test = false;
        let http_request = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let expected_data = http_request.to_vec();
        let mut proxy_server = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(58),
            false,
            is_running_in_integration_test,
        );
        proxy_server.subs = Some(make_proxy_server_out_subs());
        let inbound_client_data_msg = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: SocketAddr::from_str("1.2.3.4:4578").unwrap(),
            reception_port_opt: Some(80),
            last_data: true,
            is_clandestine: false,
            sequence_number: Some(123),
            data: expected_data,
        };

        let result = IBCDHelperReal::new().handle_normal_client_data(
            &mut proxy_server,
            inbound_client_data_msg,
            true,
        );

        assert_eq!(
            result,
            Err("Request to wildcard IP detected - localhost (Most likely because Blockchain Service URL is not set)".to_string())
        );
    }

    #[test]
    fn make_payload_passes_no_hostname_if_none_is_known() {
        let mut subject = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(58),
            false,
            false,
        );
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let client_request_payload_factory = ClientRequestPayloadFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(None);
        subject.client_request_payload_factory = Box::new(client_request_payload_factory);
        let stream_key = StreamKey::make_meaningless_stream_key();
        // Do not create an entry in subject.stream_info for stream_key, so that no hostname is known

        let _ = subject.make_payload(
            InboundClientData { // irrelevant
                timestamp: SystemTime::now(),
                client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                reception_port_opt: Some(HTTP_PORT),
                last_data: false,
                is_clandestine: false,
                sequence_number: Some(123),
                data: vec![],
            },
            &stream_key
        );

        let (_ibcd, _sk, hostname_opt, _cryptde, _logger) = &make_params_arc.lock().unwrap()[0];
        assert_eq!(hostname_opt, &None);
    }

    #[test]
    fn make_payload_passes_hostname_if_known() {
        let mut subject = ProxyServer::new(
            main_cryptde(),
            alias_cryptde(),
            true,
            Some(58),
            false,
            false,
        );
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let client_request_payload_factory = ClientRequestPayloadFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(None); // Don't care about return value, only parameters
        subject.client_request_payload_factory = Box::new(client_request_payload_factory);
        let stream_key = StreamKey::make_meaningless_stream_key();
        let si_host = Host::new("knownhostname.com", 2345);
        subject.stream_info.insert(stream_key.clone(), StreamInfo {
            tunneled_host_opt: None,
            dns_failure_retry_opt: None,
            route_opt: Some(RouteQueryResponse {
                route: Route { hops: vec![] },
                expected_services: ExpectedServices::RoundTrip(vec![], vec![]),
                host: Host::new(&si_host.name, 2345),
            }),
            protocol_opt: None,
            time_to_live_opt: None,
        });

        let _ = subject.make_payload(
            InboundClientData { // irrelevant
                timestamp: SystemTime::now(),
                client_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
                reception_port_opt: Some(HTTP_PORT),
                last_data: false,
                is_clandestine: false,
                sequence_number: Some(123),
                data: vec![],
            },
            &stream_key
        );

        let (_ibcd, _sk, host_opt, _cryptde, _logger) = &make_params_arc.lock().unwrap()[0];
        assert_eq!(host_opt, &Some(si_host));
    }

    #[test]
    #[should_panic(
        expected = "ProxyServer should never get ShutdownStreamMsg about clandestine stream"
    )]
    fn handle_stream_shutdown_complains_about_clandestine_message() {
        let system = System::new("test");
        let subject = ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, false, false);
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
        let proxy_server =
            ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, true, false);

        prove_that_crash_request_handler_is_hooked_up(proxy_server, CRASH_KEY);
    }

    #[test]
    fn find_or_generate_stream_key_prioritizes_existing_stream_key_first() {
        let socket_addr = SocketAddr::from_str("1.2.3.4:4321").unwrap();
        let stream_key = StreamKey::new(main_cryptde().public_key(), socket_addr);
        let mut subject =
            ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, false, false);
        subject.keys_and_addrs.insert(stream_key, socket_addr);
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr,
            reception_port_opt: Some(2222),
            last_data: true,
            is_clandestine: false,
            sequence_number: Some(333),
            data: b"GET /index.html HTTP/1.1\r\nHost: header.com:3333\r\n\r\n".to_vec(),
        };

        let result = subject.find_or_generate_stream_key(&ibcd);

        assert_eq!(result, stream_key);
        assert_eq!(
            subject.keys_and_addrs.a_to_b(&stream_key),
            Some(socket_addr)
        );
    }

    #[test]
    fn find_or_generate_stream_key_creates_stream_key_if_necessary() {
        let socket_addr = SocketAddr::from_str("1.2.3.4:4321").unwrap();
        let stream_key = StreamKey::new(main_cryptde().public_key(), socket_addr);
        let mut subject =
            ProxyServer::new(main_cryptde(), alias_cryptde(), true, None, false, false);
        let ibcd = InboundClientData {
            timestamp: SystemTime::now(),
            client_addr: socket_addr,
            reception_port_opt: Some(2222),
            last_data: true,
            is_clandestine: false,
            sequence_number: Some(333),
            data: b"GET /index.html HTTP/1.1\r\nHost: header.com:4444\r\n\r\n".to_vec(),
        };

        let result = subject.find_or_generate_stream_key(&ibcd);

        assert_eq!(result, stream_key);
        assert_eq!(
            subject.keys_and_addrs.a_to_b(&stream_key),
            Some(socket_addr)
        );
    }

    fn make_server_com_client_hello() -> Vec<u8> {
        [
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
        ].to_vec()
    }

    fn make_exit_service_from_key(public_key: PublicKey) -> ExpectedService {
        ExpectedService::Exit(public_key, make_wallet("exit wallet"), rate_pack(100))
    }
}
