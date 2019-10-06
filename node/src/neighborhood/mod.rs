// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

mod dot_graph;
pub mod gossip;
pub mod gossip_acceptor;
#[cfg(not(feature = "expose_test_privates"))]
mod gossip_producer;
#[cfg(feature = "expose_test_privates")]
pub mod gossip_producer;
pub mod neighborhood_database;
pub mod node_record;

#[cfg(not(feature = "expose_test_privates"))]
#[cfg(test)]
mod neighborhood_test_utils;

#[cfg(feature = "expose_test_privates")]
pub mod neighborhood_test_utils;

use crate::blockchain::blockchain_interface::contract_address;
use crate::bootstrapper::BootstrapperConfig;
use crate::neighborhood::gossip::{DotGossipEndpoint, Gossip, GossipNodeRecord};
use crate::neighborhood::gossip_acceptor::GossipAcceptanceResult;
use crate::neighborhood::node_record::NodeRecordInner;
use crate::stream_messages::RemovedStreamType;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde::{CryptDE, CryptData, PlainData};
use crate::sub_lib::dispatcher::{Component, StreamShutdownMsg};
use crate::sub_lib::hopper::{ExpiredCoresPackage, NoLookupIncipientCoresPackage};
use crate::sub_lib::hopper::{IncipientCoresPackage, MessageType};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::neighborhood::DispatcherNodeQueryMessage;
use crate::sub_lib::neighborhood::ExpectedService;
use crate::sub_lib::neighborhood::ExpectedServices;
use crate::sub_lib::neighborhood::NeighborhoodDotGraphRequest;
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::neighborhood::NodeQueryMessage;
use crate::sub_lib::neighborhood::NodeQueryResponseMetadata;
use crate::sub_lib::neighborhood::NodeRecordMetadataMessage;
use crate::sub_lib::neighborhood::RemoveNeighborMessage;
use crate::sub_lib::neighborhood::RouteQueryMessage;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::route::Route;
use crate::sub_lib::route::RouteSegment;
use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::ui_gateway::{UiCarrierMessage, UiMessage};
use crate::sub_lib::utils::{node_descriptor_delimiter, NODE_MAILBOX_CAPACITY};
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MessageResult;
use actix::Recipient;
use gossip_acceptor::GossipAcceptor;
use gossip_acceptor::GossipAcceptorReal;
use gossip_producer::GossipProducer;
use gossip_producer::GossipProducerReal;
use neighborhood_database::NeighborhoodDatabase;
use node_record::NodeRecord;
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::net::SocketAddr;

pub struct Neighborhood {
    cryptde: &'static dyn CryptDE,
    hopper: Option<Recipient<IncipientCoresPackage>>,
    hopper_no_lookup: Option<Recipient<NoLookupIncipientCoresPackage>>,
    dot_graph_recipient: Option<Recipient<UiCarrierMessage>>,
    gossip_acceptor: Box<dyn GossipAcceptor>,
    gossip_producer: Box<dyn GossipProducer>,
    neighborhood_database: NeighborhoodDatabase,
    consuming_wallet_opt: Option<Wallet>,
    next_return_route_id: u32,
    initial_neighbors: Vec<String>,
    logger: Logger,
    chain_id: u8,
}

impl Actor for Neighborhood {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.hopper = Some(msg.peer_actors.hopper.from_hopper_client);
        self.hopper_no_lookup = Some(msg.peer_actors.hopper.from_hopper_client_no_lookup);
        self.dot_graph_recipient = Some(msg.peer_actors.ui_gateway.ui_message_sub)
    }
}

impl Handler<SetConsumingWalletMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: SetConsumingWalletMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.consuming_wallet_opt = Some(msg.wallet);
    }
}

impl Handler<StartMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, _msg: StartMessage, _ctx: &mut Self::Context) -> Self::Result {
        if self.initial_neighbors.is_empty() {
            info!(self.logger, "Empty. No Nodes to report to; continuing");
            return;
        }

        let gossip = self
            .gossip_producer
            .produce_debut(&self.neighborhood_database);
        self.initial_neighbors.iter().for_each(|neighbor| {
            let node_descriptor = NodeDescriptor::from_str(self.cryptde, neighbor, self.chain_id)
                .unwrap_or_else(|e| {
                    panic!(
                        "--neighbors must be <public key>{}<ip address>:<port>;<port>..., not '{}'",
                        node_descriptor_delimiter(self.chain_id),
                        e
                    );
                });
            if let Some(node_addr) = &node_descriptor.node_addr_opt {
                self.hopper_no_lookup
                    .as_ref()
                    .expect("unbound hopper")
                    .try_send(
                        NoLookupIncipientCoresPackage::new(
                            self.cryptde,
                            &node_descriptor.public_key,
                            &node_addr,
                            MessageType::Gossip(gossip.clone()),
                        )
                        .expect("Key magically disappeared"),
                    )
                    .expect("hopper is dead");
                trace!(
                    self.logger,
                    "Sent Gossip: {}",
                    gossip.to_dot_graph(
                        self.neighborhood_database.root(),
                        (&node_descriptor.public_key, &node_descriptor.node_addr_opt),
                    )
                );
            } else {
                panic!(
                    "--neighbors node descriptors must have IP address and port list, not '{}'",
                    neighbor
                )
            }
        });
    }
}

impl Handler<NodeQueryMessage> for Neighborhood {
    type Result = MessageResult<NodeQueryMessage>;

    fn handle(
        &mut self,
        msg: NodeQueryMessage,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<NodeQueryMessage>>::Result {
        let node_record_ref_opt = match msg {
            NodeQueryMessage::IpAddress(ip_addr) => self.neighborhood_database.node_by_ip(&ip_addr),
            NodeQueryMessage::PublicKey(key) => self.neighborhood_database.node_by_key(&key),
        };

        MessageResult(match node_record_ref_opt {
            Some(node_record_ref) => Some(NodeQueryResponseMetadata::new(
                node_record_ref.public_key().clone(),
                match node_record_ref.node_addr_opt() {
                    Some(node_addr_ref) => Some(node_addr_ref.clone()),
                    None => None,
                },
                node_record_ref.rate_pack().clone(),
            )),
            None => None,
        })
    }
}

impl Handler<DispatcherNodeQueryMessage> for Neighborhood {
    type Result = ();

    fn handle(
        &mut self,
        msg: DispatcherNodeQueryMessage,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<DispatcherNodeQueryMessage>>::Result {
        let node_record_ref_opt = match msg.query {
            NodeQueryMessage::IpAddress(ip_addr) => self.neighborhood_database.node_by_ip(&ip_addr),
            NodeQueryMessage::PublicKey(key) => self.neighborhood_database.node_by_key(&key),
        };

        let node_descriptor = match node_record_ref_opt {
            Some(node_record_ref) => Some(NodeQueryResponseMetadata::new(
                node_record_ref.public_key().clone(),
                match node_record_ref.node_addr_opt() {
                    Some(node_addr) => Some(node_addr.clone()),
                    None => None,
                },
                node_record_ref.rate_pack().clone(),
            )),
            None => None,
        };

        let response = DispatcherNodeQueryResponse {
            result: node_descriptor,
            context: msg.context,
        };

        msg.recipient
            .try_send(response)
            .expect("Dispatcher's StreamHandlerPool is dead");
    }
}

impl Handler<RouteQueryMessage> for Neighborhood {
    type Result = MessageResult<RouteQueryMessage>;

    fn handle(
        &mut self,
        msg: RouteQueryMessage,
        _ctx: &mut Self::Context,
    ) -> <Self as Handler<RouteQueryMessage>>::Result {
        let msg_str = format!("{:?}", msg);
        let result = if msg.minimum_hop_count == 0 {
            Ok(self.zero_hop_route_response())
        } else {
            self.make_round_trip_route(msg)
        };
        MessageResult(match result {
            Ok(response) => {
                debug!(
                    self.logger,
                    "Processed {} into {}-hop response",
                    msg_str,
                    response.route.hops.len(),
                );
                Some(response)
            }
            Err(msg) => {
                error!(self.logger, "Unsatisfied route query: {}", msg);
                None
            }
        })
    }
}

impl Handler<ExpiredCoresPackage<Gossip>> for Neighborhood {
    type Result = ();

    fn handle(
        &mut self,
        msg: ExpiredCoresPackage<Gossip>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let incoming_gossip = msg.payload;
        self.log_incoming_gossip(&incoming_gossip, msg.immediate_neighbor);
        self.handle_gossip(incoming_gossip, msg.immediate_neighbor);
    }
}

impl Handler<RemoveNeighborMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: RemoveNeighborMessage, _ctx: &mut Self::Context) -> Self::Result {
        let public_key = &msg.public_key;
        match self.neighborhood_database.remove_neighbor(public_key) {
            Err(s) => error!(self.logger, "{}", s),
            Ok(db_changed) => {
                if db_changed {
                    self.gossip_to_neighbors();
                    info!(
                        self.logger,
                        "removed neighbor by public key: {}", public_key
                    )
                }
            }
        }
    }
}

impl Handler<NodeRecordMetadataMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: NodeRecordMetadataMessage, _ctx: &mut Self::Context) -> Self::Result {
        match msg {
            NodeRecordMetadataMessage::Desirable(public_key, desirable) => {
                if let Some(node_record) = self.neighborhood_database.node_by_key_mut(&public_key) {
                    node_record.set_desirable(desirable);
                };
            }
        };
    }
}

impl Handler<StreamShutdownMsg> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: StreamShutdownMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.handle_stream_shutdown_msg(msg);
    }
}

impl Handler<NeighborhoodDotGraphRequest> for Neighborhood {
    type Result = ();

    fn handle(
        &mut self,
        msg: NeighborhoodDotGraphRequest,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        info!(
            self.logger,
            "acknowledge request for neighborhood dot graph."
        );
        self.dot_graph_recipient
            .as_ref()
            .expect("DOT graph recipient is unbound")
            .try_send(UiCarrierMessage {
                client_id: msg.client_id,
                data: UiMessage::NeighborhoodDotGraphResponse(
                    self.neighborhood_database.to_dot_graph().clone(),
                ),
            })
            .expect("DOT graph recipient is dead")
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct AccessibleGossipRecord {
    pub signed_gossip: PlainData,
    pub signature: CryptData,
    pub node_addr_opt: Option<NodeAddr>,
    pub inner: NodeRecordInner,
}

impl AccessibleGossipRecord {
    pub fn regenerate_signed_gossip(&mut self, cryptde: &dyn CryptDE) {
        let (signed_gossip, signature) = regenerate_signed_gossip(&self.inner, cryptde);
        self.signed_gossip = signed_gossip;
        self.signature = signature;
    }
}

impl TryFrom<GossipNodeRecord> for AccessibleGossipRecord {
    type Error = String;

    fn try_from(value: GossipNodeRecord) -> Result<Self, Self::Error> {
        match serde_cbor::de::from_slice(value.signed_data.as_slice()) {
            Ok(inner) => Ok(AccessibleGossipRecord {
                signed_gossip: value.signed_data,
                signature: value.signature,
                node_addr_opt: value.node_addr_opt,
                inner,
            }),
            Err(e) => Err(format!("{}", e)),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum RouteDirection {
    Over,
    Back,
}

impl Neighborhood {
    pub fn new(cryptde: &'static dyn CryptDE, config: &BootstrapperConfig) -> Self {
        let neighborhood_config = &config.neighborhood_config;
        if neighborhood_config.mode.is_zero_hop()
            && !neighborhood_config.mode.neighbor_configs().is_empty()
        {
            panic!(
                "A zero-hop MASQ Node is not decentralized and cannot have a --neighbors setting"
            )
        }
        let gossip_acceptor: Box<dyn GossipAcceptor> = Box::new(GossipAcceptorReal::new(cryptde));
        let gossip_producer = Box::new(GossipProducerReal::new());
        let neighborhood_database = NeighborhoodDatabase::new(
            &cryptde.public_key(),
            neighborhood_config.mode.clone(),
            config.earning_wallet.clone(),
            cryptde,
        );

        Neighborhood {
            cryptde,
            hopper: None,
            hopper_no_lookup: None,
            dot_graph_recipient: None,
            gossip_acceptor,
            gossip_producer,
            neighborhood_database,
            consuming_wallet_opt: config.consuming_wallet.clone(),
            next_return_route_id: 0,
            initial_neighbors: neighborhood_config.mode.neighbor_configs().clone(),
            logger: Logger::new("Neighborhood"),
            chain_id: config.blockchain_bridge_config.chain_id,
        }
    }

    pub fn make_subs_from(addr: &Addr<Neighborhood>) -> NeighborhoodSubs {
        NeighborhoodSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            start: addr.clone().recipient::<StartMessage>(),
            node_query: addr.clone().recipient::<NodeQueryMessage>(),
            route_query: addr.clone().recipient::<RouteQueryMessage>(),
            update_node_record_metadata: addr.clone().recipient::<NodeRecordMetadataMessage>(),
            from_hopper: addr.clone().recipient::<ExpiredCoresPackage<Gossip>>(),
            dispatcher_node_query: addr.clone().recipient::<DispatcherNodeQueryMessage>(),
            remove_neighbor: addr.clone().recipient::<RemoveNeighborMessage>(),
            stream_shutdown_sub: addr.clone().recipient::<StreamShutdownMsg>(),
            set_consuming_wallet_sub: addr.clone().recipient::<SetConsumingWalletMessage>(),
            from_ui_gateway: addr.clone().recipient::<NeighborhoodDotGraphRequest>(),
        }
    }

    fn log_incoming_gossip(&self, incoming_gossip: &Gossip, gossip_source: SocketAddr) {
        let source = match self.neighborhood_database.node_by_ip(&gossip_source.ip()) {
            Some(node) => DotGossipEndpoint::from(node),
            None => DotGossipEndpoint::from(gossip_source),
        };
        trace!(
            self.logger,
            "Received Gossip: {}",
            incoming_gossip.to_dot_graph(source, self.neighborhood_database.root())
        );
    }

    fn handle_gossip(&mut self, incoming_gossip: Gossip, gossip_source: SocketAddr) {
        info!(
            self.logger,
            "Processing Gossip about {} Nodes",
            incoming_gossip.node_records.len()
        );

        let record_count = incoming_gossip.node_records.len();
        let agrs: Vec<AccessibleGossipRecord> = incoming_gossip
            .node_records
            .into_iter()
            .flat_map(AccessibleGossipRecord::try_from)
            .collect();

        if agrs.len() < record_count {
            // TODO: Instead of ignoring non-deserializable Gossip, ban the Node that sent it
            error!(
                self.logger,
                "Received non-deserializable Gossip from {}", gossip_source
            );
            self.announce_gossip_handling_completion(record_count);
            return;
        }

        let signature_invalid = |agr: &AccessibleGossipRecord| {
            !self.cryptde.verify_signature(
                &agr.signed_gossip,
                &agr.signature,
                &agr.inner.public_key,
            )
        };
        if agrs.iter().any(signature_invalid) {
            // TODO: Instead of ignoring badly-signed Gossip, ban the Node that sent it
            error!(
                self.logger,
                "Received Gossip with invalid signature from {}", gossip_source
            );
            self.announce_gossip_handling_completion(record_count);
            return;
        }

        self.handle_agrs(agrs, gossip_source);
        self.announce_gossip_handling_completion(record_count);
    }

    fn handle_agrs(&mut self, agrs: Vec<AccessibleGossipRecord>, gossip_source: SocketAddr) {
        let ignored_node_name = self.gossip_source_name(&agrs, gossip_source);
        let gossip_record_count = agrs.len();
        let acceptance_result =
            self.gossip_acceptor
                .handle(&mut self.neighborhood_database, agrs, gossip_source);
        match acceptance_result {
            GossipAcceptanceResult::Accepted => self.gossip_to_neighbors(),
            GossipAcceptanceResult::Reply(next_debut, relay_target, relay_node_addr) => {
                self.handle_gossip_reply(next_debut, relay_target, relay_node_addr)
            }
            GossipAcceptanceResult::Ignored => {
                trace!(self.logger, "Gossip from {} ignored", gossip_source);
                self.handle_gossip_ignored(ignored_node_name, gossip_record_count)
            }
            GossipAcceptanceResult::Ban(reason) => {
                warning!(self.logger, "Malefactor detected at {}, but malefactor bans not yet implemented; ignoring: {}", gossip_source, reason
            );
                self.handle_gossip_ignored(ignored_node_name, gossip_record_count);
            }
        }
    }

    fn announce_gossip_handling_completion(&self, record_count: usize) {
        info!(
            self.logger,
            "Finished processing Gossip about {} Nodes", record_count
        );
    }

    fn gossip_to_neighbors(&mut self) {
        self.neighborhood_database
            .root_mut()
            .regenerate_signed_gossip(self.cryptde);
        let neighbors = self.neighborhood_database.root().half_neighbor_keys();
        neighbors.iter().for_each(|neighbor| {
            let gossip = self
                .gossip_producer
                .produce(&self.neighborhood_database, neighbor);
            let gossip_len = gossip.node_records.len();
            let route = self.create_single_hop_route(neighbor);
            let package =
                IncipientCoresPackage::new(self.cryptde, route, gossip.clone().into(), neighbor)
                    .expect("Key magically disappeared");
            info!(
                self.logger,
                "Sending update Gossip about {} Nodes to Node {}", gossip_len, neighbor
            );
            self.hopper
                .as_ref()
                .expect("unbound hopper")
                .try_send(package)
                .expect("hopper is dead");
            trace!(
                self.logger,
                "Sent Gossip: {}",
                gossip.to_dot_graph(
                    self.neighborhood_database.root(),
                    self.neighborhood_database
                        .node_by_key(*neighbor)
                        .expect("Node magically disappeared"),
                )
            );
        });
    }

    fn create_single_hop_route(&self, destination: &PublicKey) -> Route {
        Route::one_way(
            RouteSegment::new(
                vec![&self.cryptde.public_key(), destination],
                Component::Neighborhood,
            ),
            self.cryptde,
            None,
            None,
        )
        .expect("route creation error")
    }

    fn zero_hop_route_response(&mut self) -> RouteQueryResponse {
        let return_route_id = self.advance_return_route_id();
        let route = Route::round_trip(
            RouteSegment::new(
                vec![&self.cryptde.public_key(), &self.cryptde.public_key()],
                Component::ProxyClient,
            ),
            RouteSegment::new(
                vec![&self.cryptde.public_key(), &self.cryptde.public_key()],
                Component::ProxyServer,
            ),
            self.cryptde,
            None,
            return_route_id,
            None,
        )
        .expect("Couldn't create route");
        RouteQueryResponse {
            route,
            expected_services: ExpectedServices::RoundTrip(
                vec![ExpectedService::Nothing, ExpectedService::Nothing],
                vec![ExpectedService::Nothing, ExpectedService::Nothing],
                return_route_id,
            ),
        }
    }

    fn make_round_trip_route(
        &mut self,
        msg: RouteQueryMessage,
    ) -> Result<RouteQueryResponse, String> {
        let over = self.make_route_segment(
            &self.cryptde.public_key(),
            msg.target_key_opt.as_ref(),
            msg.minimum_hop_count,
            msg.target_component,
            RouteDirection::Over,
        )?;
        debug!(self.logger, "Route over: {:?}", over);
        let back = self.make_route_segment(
            over.keys.last().expect("Empty segment"),
            Some(&self.cryptde.public_key()),
            msg.minimum_hop_count,
            msg.return_component_opt.expect("No return component"),
            RouteDirection::Back,
        )?;
        debug!(self.logger, "Route back: {:?}", back);
        self.compose_route_query_response(over, back)
    }

    fn compose_route_query_response(
        &mut self,
        over: RouteSegment,
        back: RouteSegment,
    ) -> Result<RouteQueryResponse, String> {
        let segments = vec![&over, &back];

        if segments.iter().any(|rs| rs.keys.is_empty()) {
            return Err("Cannot make multi-hop route without segment keys".to_string());
        }

        let has_long_segment = segments.iter().any(|segment| segment.keys.len() > 2);
        if self.consuming_wallet_opt.is_none() && has_long_segment {
            return Err("Cannot make multi-hop route segment without consuming wallet".to_string());
        }

        let expected_request_services = match self.make_expected_services(&over) {
            Ok(services) => services,
            Err(e) => return Err(e),
        };

        let expected_response_services = match self.make_expected_services(&back) {
            Ok(services) => services,
            Err(e) => return Err(e),
        };

        let return_route_id = self.advance_return_route_id();
        Ok(RouteQueryResponse {
            route: Route::round_trip(
                over,
                back,
                self.cryptde,
                self.consuming_wallet_opt.clone(),
                return_route_id,
                Some(contract_address(self.chain_id)),
            )
            .expect("Internal error: bad route"),
            expected_services: ExpectedServices::RoundTrip(
                expected_request_services,
                expected_response_services,
                return_route_id,
            ),
        })
    }

    fn make_route_segment(
        &self,
        origin: &PublicKey,
        target: Option<&PublicKey>,
        minimum_hop_count: usize,
        target_component: Component,
        direction: RouteDirection,
    ) -> Result<RouteSegment, String> {
        let mut node_seqs =
            self.complete_routes(vec![origin], target, minimum_hop_count, direction);

        if node_seqs.is_empty() {
            let target_str = match target {
                Some(t) => format!(" {}", t),
                None => String::from("Unknown"),
            };
            Err(format!(
                "Couldn't find any routes: at least {}-hop from {} to {:?} at {}",
                minimum_hop_count, origin, target_component, target_str
            ))
        } else {
            // When the target is Some all exit nodes will be the target and it is not optimal to sort.
            if target.is_none() {
                self.sort_routes_by_desirable_exit_nodes(node_seqs.as_mut());
            }
            let chosen_node_seq = node_seqs.remove(0);
            Ok(RouteSegment::new(chosen_node_seq, target_component))
        }
    }

    fn sort_routes_by_desirable_exit_nodes(&self, node_seqs: &mut Vec<Vec<&PublicKey>>) {
        if node_seqs.is_empty() {
            panic!("Unable to sort routes by desirable exit nodes: Missing routes.");
        }
        let get_the_exit_nodes_desirable_flag = |vec: &Vec<&PublicKey>| -> Option<bool> {
            vec.last()
                .and_then(|pk|
                    Some(
                        self.neighborhood_database
                            .node_by_key(pk)
                            .unwrap_or_else(|| panic!("Unable to sort routes by desirable exit nodes: Missing NodeRecord for public key: [{}]", pk))
                    )
                ).map(|node| node.is_desirable())
        };

        node_seqs.sort_by(|vec1: &Vec<&PublicKey>, vec2: &Vec<&PublicKey>| {
            if vec1.is_empty() || vec2.is_empty() {
                panic!("Unable to sort routes by desirable exit nodes: Missing route segments.")
            }
            let is_desirable1 = get_the_exit_nodes_desirable_flag(vec1);
            let is_desirable2 = get_the_exit_nodes_desirable_flag(vec2);
            match (is_desirable1, is_desirable2) {
                (Some(true), Some(false)) => Ordering::Less,
                (Some(false), Some(true)) => Ordering::Greater,
                _ => Ordering::Equal,
            }
        });
    }

    fn make_expected_services(
        &self,
        segment: &RouteSegment,
    ) -> Result<Vec<ExpectedService>, String> {
        segment
            .keys
            .iter()
            .map(|ref key| {
                self.calculate_expected_service(key, segment.keys.first(), segment.keys.last())
            })
            .collect()
    }

    fn calculate_expected_service(
        &self,
        route_segment_key: &PublicKey,
        originator_key: Option<&PublicKey>,
        exit_key: Option<&PublicKey>,
    ) -> Result<ExpectedService, String> {
        match self.neighborhood_database.node_by_key(route_segment_key) {
            Some(node) => {
                if route_segment_key == self.neighborhood_database.root().public_key() {
                    Ok(ExpectedService::Nothing)
                } else {
                    match (originator_key, exit_key) {
                        (Some(originator_key), Some(exit_key))
                            if route_segment_key == originator_key
                                || route_segment_key == exit_key =>
                        {
                            Ok(ExpectedService::Exit(
                                route_segment_key.clone(),
                                node.earning_wallet(),
                                node.rate_pack().clone(),
                            ))
                        }
                        (Some(_), Some(_)) => Ok(ExpectedService::Routing(
                            route_segment_key.clone(),
                            node.earning_wallet(),
                            node.rate_pack().clone(),
                        )),
                        _ => Err(
                            "cannot calculate expected service, no keys provided in route segment"
                                .to_string(),
                        ),
                    }
                }
            }
            None => Err("Cannot make multi_hop with unknown neighbor".to_string()),
        }
    }

    fn route_length_qualifies(&self, hops_remaining: usize) -> bool {
        hops_remaining == 0
    }

    fn last_key_qualifies(
        &self,
        last_node_ref: &NodeRecord,
        target_key_ref_opt: Option<&PublicKey>,
    ) -> bool {
        match target_key_ref_opt {
            Some(target_key_ref) => last_node_ref.public_key() == target_key_ref,
            None => true,
        }
    }

    fn validate_last_node_not_too_close_to_first_node(
        &self,
        prefix_len: usize,
        first_node_key: &PublicKey,
        candidate_node_key: &PublicKey,
    ) -> bool {
        if prefix_len <= 2 {
            true // Zero- and single-hop routes are not subject to exit-too-close restrictions
        } else {
            !self
                .neighborhood_database
                .has_half_neighbor(candidate_node_key, first_node_key)
        }
    }

    fn is_orig_node_on_back_leg(
        node: &NodeRecord,
        target_key_opt: Option<&PublicKey>,
        direction: RouteDirection,
    ) -> bool {
        match direction {
            RouteDirection::Over => false,
            RouteDirection::Back => match target_key_opt {
                None => false,
                Some(target_key) => node.public_key() == target_key,
            },
        }
    }

    fn advance_return_route_id(&mut self) -> u32 {
        let return_route_id = self.next_return_route_id;
        self.next_return_route_id = return_route_id.wrapping_add(1);
        return_route_id
    }

    // Main recursive routing engine. Supply origin key as single-element vector in prefix,
    // target key, if any, in target, and minimum hop count in hops_remaining. Return value is
    // a list of all the node sequences that will either go from the origin to the target in
    // hops_remaining or more hops with no cycles, or from the origin hops_remaining hops out into
    // the Substratum Network. No round trips; if you want a round trip, call this method twice.
    // If the return value is empty, no qualifying route was found.
    fn complete_routes<'a>(
        &'a self,
        prefix: Vec<&'a PublicKey>,
        target_opt: Option<&'a PublicKey>,
        hops_remaining: usize,
        direction: RouteDirection,
    ) -> Vec<Vec<&'a PublicKey>> {
        let first_node_key = prefix.first().expect("Empty prefix");
        let previous_node = self
            .neighborhood_database
            .node_by_key(prefix.last().expect("Empty prefix"))
            .expect("Last Node magically disappeared");
        // Check to see if we're done. If we are, all three of these qualifications will pass.
        if self.route_length_qualifies(hops_remaining)
            && self.last_key_qualifies(previous_node, target_opt)
            && self.validate_last_node_not_too_close_to_first_node(
                prefix.len(),
                *first_node_key,
                previous_node.public_key(),
            )
        {
            vec![prefix]
        } else if (hops_remaining == 0) && target_opt.is_none() {
            // don't continue a targetless search past the minimum hop count
            vec![]
        } else {
            // Go through all the neighbors and compute shorter routes through all the ones we're not already using.
            previous_node
                .full_neighbors(&self.neighborhood_database)
                .iter()
                .filter(|node_record| !prefix.contains(&node_record.public_key()))
                .filter(|node_record| {
                    node_record.routes_data()
                        || Self::is_orig_node_on_back_leg(**node_record, target_opt, direction)
                })
                .flat_map(|node_record| {
                    let mut new_prefix = prefix.clone();
                    new_prefix.push(node_record.public_key());

                    let new_hops_remaining = if hops_remaining == 0 {
                        0
                    } else {
                        hops_remaining - 1
                    };

                    self.complete_routes(
                        new_prefix.clone(),
                        target_opt,
                        new_hops_remaining,
                        direction,
                    )
                })
                .collect()
        }
    }

    fn handle_gossip_reply(
        &self,
        next_debut_gossip: Gossip,
        relay_target: PublicKey,
        relay_node_addr: NodeAddr,
    ) {
        self.send_gossip(next_debut_gossip, relay_target, relay_node_addr);
    }

    fn handle_gossip_ignored(&self, _ignored_node_name: String, _gossip_record_count: usize) {
        // Maybe something here eventually for keeping statistics
    }

    fn send_gossip(&self, gossip: Gossip, target_key: PublicKey, target_node_addr: NodeAddr) {
        let package = match NoLookupIncipientCoresPackage::new(
            self.cryptde,
            &target_key,
            &target_node_addr,
            MessageType::Gossip(gossip.clone()),
        ) {
            Ok(p) => p,
            Err(e) => {
                error!(self.logger, "{}", e);
                return;
            }
        };
        self.hopper_no_lookup
            .as_ref()
            .expect("No-lookup Hopper is unbound")
            .try_send(package)
            .expect("Hopper is dead");
        trace!(
            self.logger,
            "Sent Gossip: {}",
            gossip.to_dot_graph(
                self.neighborhood_database.root(),
                (&target_key, &Some(target_node_addr)),
            )
        );
    }

    fn gossip_source_name(
        &self,
        accessible_gossip: &Vec<AccessibleGossipRecord>,
        gossip_source: SocketAddr,
    ) -> String {
        match accessible_gossip.iter().find(|agr| {
            if let Some(ref node_addr) = agr.node_addr_opt {
                node_addr.ip_addr() == gossip_source.ip()
            } else {
                false
            }
        }) {
            Some(agr) => format!("{}", agr.inner.public_key),
            None => format!("{}", gossip_source),
        }
    }

    fn handle_stream_shutdown_msg(&mut self, msg: StreamShutdownMsg) {
        if msg.stream_type != RemovedStreamType::Clandestine {
            panic!("Neighborhood should never get ShutdownStreamMsg about non-clandestine stream")
        }
        let neighbor_key = match self.neighborhood_database.node_by_ip(&msg.peer_addr.ip()) {
            None => {
                warning!(self.logger, "Received shutdown notification for stream to {}, but no Node with that IP is in the database - ignoring", msg.peer_addr.ip());
                return;
            }
            Some(n) => (n.public_key().clone()),
        };
        self.remove_neighbor(&neighbor_key, &msg.peer_addr);
    }

    fn remove_neighbor(&mut self, neighbor_key: &PublicKey, peer_addr: &SocketAddr) {
        match self.neighborhood_database.remove_neighbor(neighbor_key) {
            Err(_) => panic!("Node suddenly disappeared"),
            Ok(true) => {
                debug!(
                    self.logger,
                    "Received shutdown notification for {} at {}: removing neighborship",
                    neighbor_key,
                    peer_addr.ip()
                );
                self.gossip_to_neighbors()
            }
            Ok(false) => {
                debug!(self.logger, "Received shutdown notification for {} at {}, but that Node is no neighbor - ignoring", neighbor_key, peer_addr.ip());
            }
        };
    }
}

pub fn regenerate_signed_gossip(
    inner: &NodeRecordInner,
    cryptde: &dyn CryptDE, // Must be the correct CryptDE for the Node from which inner came: used for signing
) -> (PlainData, CryptData) {
    let signed_gossip =
        PlainData::from(serde_cbor::ser::to_vec(&inner).expect("Serialization failed"));
    let signature = match cryptde.sign(&signed_gossip) {
        Ok(sig) => sig,
        Err(e) => unimplemented!("Signing error: {:?}", e),
    };
    (signed_gossip, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::blockchain_interface::contract_address;
    use crate::neighborhood::gossip::Gossip;
    use crate::neighborhood::gossip::GossipBuilder;
    use crate::neighborhood::neighborhood_test_utils::*;
    use crate::neighborhood::node_record::NodeRecordInner;
    use crate::persistent_configuration::TLS_PORT;
    use crate::stream_messages::{NonClandestineAttributes, RemovedStreamType};
    use crate::sub_lib::cryptde::{decodex, encodex, CryptData};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::dispatcher::Endpoint;
    use crate::sub_lib::hop::LiveHop;
    use crate::sub_lib::hopper::MessageType;
    use crate::sub_lib::neighborhood::{ExpectedServices, NeighborhoodMode};
    use crate::sub_lib::neighborhood::{NeighborhoodConfig, DEFAULT_RATE_PACK};
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::rate_pack;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::vec_to_set;
    use crate::test_utils::{assert_contains, make_wallet};
    use crate::test_utils::{assert_matches, make_meaningless_route};
    use crate::test_utils::{cryptde, make_paying_wallet, DEFAULT_CHAIN_ID};
    use actix::dev::{MessageResponse, ResponseChannel};
    use actix::Message;
    use actix::Recipient;
    use actix::System;
    use itertools::Itertools;
    use serde_cbor;
    use std::cell::RefCell;
    use std::convert::TryInto;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tokio::prelude::Future;

    #[test]
    fn node_with_zero_hop_config_creates_single_node_database() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");

        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::ZeroHop,
                },
                earning_wallet.clone(),
                None,
            ),
        );

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(root_node_record_ref.public_key(), cryptde.public_key());
        assert_eq!(root_node_record_ref.node_addr_opt(), None);
        assert_eq!(root_node_record_ref.half_neighbor_keys().len(), 0);
    }

    #[test]
    fn node_with_originate_only_config_is_decentralized_with_neighbor_but_not_ip() {
        let cryptde = cryptde();
        let neighbor: NodeRecord = make_node_record(1234, true);
        let earning_wallet = make_wallet("earning");

        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::OriginateOnly(
                        vec![neighbor.node_descriptor(cryptde, DEFAULT_CHAIN_ID)],
                        DEFAULT_RATE_PACK.clone(),
                    ),
                },
                earning_wallet.clone(),
                None,
            ),
        );

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(root_node_record_ref.public_key(), cryptde.public_key());
        assert_eq!(root_node_record_ref.accepts_connections(), false);
        assert_eq!(root_node_record_ref.routes_data(), true);
        assert_eq!(root_node_record_ref.node_addr_opt(), None);
        assert_eq!(root_node_record_ref.half_neighbor_keys().len(), 0);
    }

    #[test]
    fn node_with_zero_hop_config_ignores_start_message() {
        init_test_logging();
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let system =
            System::new("node_with_no_neighbor_configs_ignores_bootstrap_neighborhood_now_message");
        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::ZeroHop,
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
            ),
        );
        let addr: Addr<Neighborhood> = subject.start();
        let sub = addr.clone().recipient::<StartMessage>();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        addr.try_send(BindMessage { peer_actors }).unwrap();

        sub.try_send(StartMessage {}).unwrap();

        System::current().stop_with_code(0);
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
        TestLogHandler::new()
            .exists_log_containing("INFO: Neighborhood: Empty. No Nodes to report to; continuing");
    }

    #[test]
    #[should_panic(
        expected = "--neighbors must be <public key>:<ip address>:<port>;<port>..., not 'ooga'"
    )]
    fn node_with_bad_neighbor_config_panics() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let system = System::new("node_with_bad_neighbor_config_panics");
        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]),
                        vec![String::from("ooga"), String::from("booga")],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
            ),
        );
        let addr: Addr<Neighborhood> = subject.start();
        let sub = addr.clone().recipient::<StartMessage>();
        let peer_actors = peer_actors_builder().build();
        addr.try_send(BindMessage { peer_actors }).unwrap();

        sub.try_send(StartMessage {}).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[test]
    #[should_panic(
        expected = "--neighbors node descriptors must have IP address and port list, not 'AwQFBg::'"
    )]
    fn node_with_neighbor_config_having_no_node_addr_panics() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let neighbor_node = make_node_record(3456, true);
        let system = System::new("node_with_bad_neighbor_config_panics");
        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]),
                        vec![NodeDescriptor::from(neighbor_node.public_key())
                            .to_string(cryptde, DEFAULT_CHAIN_ID)],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
            ),
        );
        let addr: Addr<Neighborhood> = subject.start();
        let sub = addr.clone().recipient::<StartMessage>();
        let peer_actors = peer_actors_builder().build();
        addr.try_send(BindMessage { peer_actors }).unwrap();

        sub.try_send(StartMessage {}).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[test]
    fn neighborhood_adds_nodes_and_links() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let one_neighbor_node = make_node_record(3456, true);
        let another_neighbor_node = make_node_record(4567, true);
        let this_node_addr = NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]);

        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        this_node_addr.clone(),
                        vec![
                            NodeDescriptor::from(&one_neighbor_node)
                                .to_string(cryptde, DEFAULT_CHAIN_ID),
                            NodeDescriptor::from(&another_neighbor_node)
                                .to_string(cryptde, DEFAULT_CHAIN_ID),
                        ],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
            ),
        );

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(
            root_node_record_ref.node_addr_opt().unwrap().clone(),
            this_node_addr
        );

        assert_eq!(
            root_node_record_ref.has_half_neighbor(one_neighbor_node.public_key()),
            false,
        );
        assert_eq!(
            root_node_record_ref.has_half_neighbor(another_neighbor_node.public_key()),
            false,
        );
        assert_eq!(
            subject.initial_neighbors,
            vec![
                NodeDescriptor::from(&one_neighbor_node).to_string(cryptde, DEFAULT_CHAIN_ID),
                NodeDescriptor::from(&another_neighbor_node).to_string(cryptde, DEFAULT_CHAIN_ID)
            ]
        );
    }

    #[test]
    fn node_query_responds_with_none_when_initially_configured_with_no_data() {
        let system = System::new("responds_with_none_when_initially_configured_with_no_data");
        let subject = make_standard_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::PublicKey(PublicKey::new(&b"booga"[..])));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn node_query_responds_with_none_when_key_query_matches_no_configured_data() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let system =
            System::new("node_query_responds_with_none_when_key_query_matches_no_configured_data");
        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]),
                        vec![NodeDescriptor::from((
                            &PublicKey::new(&b"booga"[..]),
                            &NodeAddr::new(
                                &IpAddr::from_str("1.2.3.4").unwrap(),
                                &vec![1234, 2345],
                            ),
                        ))
                        .to_string(cryptde, DEFAULT_CHAIN_ID)],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
            ),
        );
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::PublicKey(PublicKey::new(&b"blah"[..])));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn node_query_responds_with_result_when_key_query_matches_configured_data() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let system =
            System::new("node_query_responds_with_result_when_key_query_matches_configured_data");
        let one_neighbor = make_node_record(2345, true);
        let another_neighbor = make_node_record(3456, true);
        let mut subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]),
                        vec![node_record_to_neighbor_config(&one_neighbor, cryptde)],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
            ),
        );
        subject
            .neighborhood_database
            .add_node(another_neighbor.clone())
            .unwrap();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::PublicKey(
            another_neighbor.public_key().clone(),
        ));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(
            result.unwrap(),
            NodeQueryResponseMetadata::new(
                another_neighbor.public_key().clone(),
                Some(another_neighbor.node_addr_opt().unwrap().clone()),
                another_neighbor.rate_pack().clone(),
            )
        );
    }

    #[test]
    fn node_query_responds_with_none_when_ip_address_query_matches_no_configured_data() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let system = System::new(
            "node_query_responds_with_none_when_ip_address_query_matches_no_configured_data",
        );
        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]),
                        vec![NodeDescriptor::from((
                            &PublicKey::new(&b"booga"[..]),
                            &NodeAddr::new(
                                &IpAddr::from_str("1.2.3.4").unwrap(),
                                &vec![1234, 2345],
                            ),
                        ))
                        .to_string(cryptde, DEFAULT_CHAIN_ID)],
                        rate_pack(100),
                    ),
                },
                earning_wallet.clone(),
                consuming_wallet.clone(),
            ),
        );
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::IpAddress(
            IpAddr::from_str("2.3.4.5").unwrap(),
        ));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn node_query_responds_with_result_when_ip_address_query_matches_configured_data() {
        let cryptde = cryptde();
        let system = System::new(
            "node_query_responds_with_result_when_ip_address_query_matches_configured_data",
        );
        let node_record = make_node_record(1234, true);
        let another_node_record = make_node_record(2345, true);
        let mut subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        node_record.node_addr_opt().unwrap(),
                        vec![
                            NodeDescriptor::from(&node_record).to_string(cryptde, DEFAULT_CHAIN_ID)
                        ],
                        rate_pack(100),
                    ),
                },
                node_record.earning_wallet(),
                None,
            ),
        );
        subject
            .neighborhood_database
            .add_node(another_node_record.clone())
            .unwrap();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::IpAddress(
            IpAddr::from_str("2.3.4.5").unwrap(),
        ));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(
            result.unwrap(),
            NodeQueryResponseMetadata::new(
                another_node_record.public_key().clone(),
                Some(another_node_record.node_addr_opt().unwrap().clone()),
                another_node_record.rate_pack().clone(),
            )
        );
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_route_with_too_many_hops() {
        let system =
            System::new("route_query_responds_with_none_when_asked_for_route_with_too_many_hops");
        let subject = make_standard_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let future = sub.send(RouteQueryMessage::data_indefinite_route_request(5));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_two_hop_round_trip_route_without_consuming_wallet(
    ) {
        let system = System::new("route_query_responds_with_none_when_asked_for_two_hop_round_trip_route_without_consuming_wallet");
        let subject = make_standard_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let future = sub.send(RouteQueryMessage::data_indefinite_route_request(2));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_succeeds_when_asked_for_one_hop_round_trip_route_without_consuming_wallet() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let system = System::new(
            "route_query_succeeds_when_asked_for_one_hop_round_trip_route_without_consuming_wallet",
        );
        let mut subject = make_standard_subject();
        subject
            .neighborhood_database
            .root_mut()
            .set_earning_wallet(earning_wallet);
        subject.consuming_wallet_opt = None;
        // These happen to be extracted in the desired order. We could not think of a way to guarantee it.
        let mut undesirable_exit_node = make_node_record(2345, true);
        let desirable_exit_node = make_node_record(3456, false);
        undesirable_exit_node.set_desirable(false);
        let originating_node = &subject.neighborhood_database.root().clone();
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(undesirable_exit_node.clone()).unwrap();
            db.add_node(desirable_exit_node.clone()).unwrap();
            db.add_arbitrary_full_neighbor(
                undesirable_exit_node.public_key(),
                originating_node.public_key(),
            );
            db.add_arbitrary_full_neighbor(
                desirable_exit_node.public_key(),
                originating_node.public_key(),
            );
        }
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();
        let msg = RouteQueryMessage::data_indefinite_route_request(1);

        let future = sub.send(msg);

        System::current().stop_with_code(0);
        system.run();
        let segment = |nodes: Vec<&NodeRecord>, component: Component| {
            RouteSegment::new(
                nodes.into_iter().map(|n| n.public_key()).collect(),
                component,
            )
        };
        let result = future.wait().unwrap().unwrap();
        let expected_response = RouteQueryResponse {
            route: Route::round_trip(
                segment(
                    vec![originating_node, &desirable_exit_node],
                    Component::ProxyClient,
                ),
                segment(
                    vec![&desirable_exit_node, originating_node],
                    Component::ProxyServer,
                ),
                cryptde,
                None,
                0,
                None,
            )
            .unwrap(),
            expected_services: ExpectedServices::RoundTrip(
                vec![
                    ExpectedService::Nothing,
                    ExpectedService::Exit(
                        desirable_exit_node.public_key().clone(),
                        desirable_exit_node.earning_wallet(),
                        rate_pack(3456),
                    ),
                ],
                vec![
                    ExpectedService::Exit(
                        desirable_exit_node.public_key().clone(),
                        desirable_exit_node.earning_wallet(),
                        rate_pack(3456),
                    ),
                    ExpectedService::Nothing,
                ],
                0,
            ),
        };
        assert_eq!(expected_response, result);
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_one_hop_round_trip_route_without_consuming_wallet_when_back_route_needs_two_hops(
    ) {
        let system = System::new("route_query_responds_with_none_when_asked_for_one_hop_round_trip_route_without_consuming_wallet_when_back_route_needs_two_hops");
        let mut subject = make_standard_subject();
        let a = &make_node_record(1234, true);
        let b = &subject.neighborhood_database.root().clone();
        let c = &make_node_record(3456, true);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(a.clone()).unwrap();
            db.add_node(c.clone()).unwrap();
            let mut single_edge = |a: &NodeRecord, b: &NodeRecord| {
                db.add_arbitrary_half_neighbor(a.public_key(), b.public_key())
            };
            single_edge(a, b);
            single_edge(b, c);
            single_edge(c, a);
        }
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();
        let msg = RouteQueryMessage::data_indefinite_route_request(1);

        let future = sub.send(msg);

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_two_hop_one_way_route_without_consuming_wallet(
    ) {
        let system = System::new("route_query_responds_with_none_when_asked_for_two_hop_one_way_route_without_consuming_wallet");
        let subject = make_standard_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();
        let msg = RouteQueryMessage::data_indefinite_route_request(2);

        let future = sub.send(msg);

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_responds_with_standard_zero_hop_route_when_requested() {
        let cryptde = cryptde();
        let system = System::new("responds_with_standard_zero_hop_route_when_requested");
        let subject = make_standard_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let future = sub.send(RouteQueryMessage::data_indefinite_route_request(0));

        System::current().stop_with_code(0);
        system.run();
        let result = future.wait().unwrap().unwrap();
        let expected_response = RouteQueryResponse {
            route: Route::round_trip(
                RouteSegment::new(
                    vec![&cryptde.public_key(), &cryptde.public_key()],
                    Component::ProxyClient,
                ),
                RouteSegment::new(
                    vec![&cryptde.public_key(), &cryptde.public_key()],
                    Component::ProxyServer,
                ),
                cryptde,
                None,
                0,
                None,
            )
            .unwrap(),
            expected_services: ExpectedServices::RoundTrip(
                vec![ExpectedService::Nothing, ExpectedService::Nothing],
                vec![ExpectedService::Nothing, ExpectedService::Nothing],
                0,
            ),
        };
        assert_eq!(result, expected_response);
    }

    #[test]
    fn zero_hop_routing_handles_return_route_id_properly() {
        let mut subject = make_standard_subject();
        let result0 = subject.zero_hop_route_response();
        let result1 = subject.zero_hop_route_response();

        let return_route_id_0 = match result0.expected_services {
            ExpectedServices::RoundTrip(_, _, id) => id,
            _ => panic!("expected RoundTrip got OneWay"),
        };

        let return_route_id_1 = match result1.expected_services {
            ExpectedServices::RoundTrip(_, _, id) => id,
            _ => panic!("expected RoundTrip got OneWay"),
        };

        assert_eq!(return_route_id_0, 0);
        assert_eq!(return_route_id_1, 1);
    }

    /*
            Database:

                 P---Q---R---S
                     |
                     T

            Tests will be written from the viewpoint of P.
    */

    #[test]
    fn route_query_messages() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let system = System::new("route_query_messages");
        let mut subject = make_standard_subject();
        subject
            .neighborhood_database
            .root_mut()
            .set_earning_wallet(earning_wallet);
        let consuming_wallet_opt = subject.consuming_wallet_opt.clone();
        let p = &subject.neighborhood_database.root().clone();
        let q = &make_node_record(3456, true);
        let r = &make_node_record(4567, false);
        let s = &make_node_record(5678, false);
        let mut t = make_node_record(1111, false);
        t.set_desirable(false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(q.clone()).unwrap();
            db.add_node(t.clone()).unwrap();
            db.add_node(r.clone()).unwrap();
            db.add_node(s.clone()).unwrap();
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| {
                db.add_arbitrary_full_neighbor(a.public_key(), b.public_key());
            };
            dual_edge(p, q);
            dual_edge(q, &t);
            dual_edge(q, r);
            dual_edge(r, s);
        }

        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let data_route = sub.send(RouteQueryMessage::data_indefinite_route_request(2));

        System::current().stop_with_code(0);
        system.run();

        let result = data_route.wait().unwrap().unwrap();
        let contract_address = contract_address(DEFAULT_CHAIN_ID);
        let expected_response = RouteQueryResponse {
            route: Route::round_trip(
                segment(&[p, q, r], &Component::ProxyClient),
                segment(&[r, q, p], &Component::ProxyServer),
                cryptde,
                consuming_wallet_opt,
                0,
                Some(contract_address),
            )
            .unwrap(),
            expected_services: ExpectedServices::RoundTrip(
                vec![
                    ExpectedService::Nothing,
                    ExpectedService::Routing(
                        q.public_key().clone(),
                        q.earning_wallet(),
                        rate_pack(3456),
                    ),
                    ExpectedService::Exit(
                        r.public_key().clone(),
                        r.earning_wallet(),
                        rate_pack(4567),
                    ),
                ],
                vec![
                    ExpectedService::Exit(
                        r.public_key().clone(),
                        r.earning_wallet(),
                        rate_pack(4567),
                    ),
                    ExpectedService::Routing(
                        q.public_key().clone(),
                        q.earning_wallet(),
                        rate_pack(3456),
                    ),
                    ExpectedService::Nothing,
                ],
                0,
            ),
        };
        assert_eq!(expected_response, result);
    }

    #[test]
    fn sort_routes_by_desirable_exit_nodes() {
        let mut subject = make_standard_subject();

        let us = subject.neighborhood_database.root().clone();
        let routing_node = make_node_record(0000, true);
        let desirable_node = make_node_record(1111, false);
        let mut undesirable_node = make_node_record(2222, false);
        undesirable_node.set_desirable(false);

        subject
            .neighborhood_database
            .add_node(routing_node.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(undesirable_node.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(desirable_node.clone())
            .unwrap();

        let mut node_sequences = Vec::new();
        node_sequences.push(vec![
            us.public_key(),
            routing_node.public_key(),
            undesirable_node.public_key(),
        ]);
        node_sequences.push(vec![
            us.public_key(),
            routing_node.public_key(),
            desirable_node.public_key(),
        ]);

        subject.sort_routes_by_desirable_exit_nodes(&mut node_sequences);

        assert_eq!(desirable_node.public_key(), node_sequences[0][2]);
        assert_eq!(undesirable_node.public_key(), node_sequences[1][2]);
    }

    #[test]
    #[should_panic(expected = "Unable to sort routes by desirable exit nodes: Missing routes.")]
    fn sort_routes_by_desirable_exit_nodes_panics_with_empty_node_sequences() {
        let subject = make_standard_subject();

        let mut node_sequences: Vec<Vec<&PublicKey>> = Vec::new();
        subject.sort_routes_by_desirable_exit_nodes(&mut node_sequences);
    }

    #[test]
    #[should_panic(
        expected = "Unable to sort routes by desirable exit nodes: Missing route segments."
    )]
    fn sort_routes_by_desirable_exit_nodes_panics_with_the_first_route_segment_empty() {
        let subject = make_standard_subject();

        let mut node_sequences: Vec<Vec<&PublicKey>> = Vec::new();
        let public_key = &PublicKey::from(&b"1234"[..]);
        node_sequences.push(vec![]);
        node_sequences.push(vec![public_key]);

        subject.sort_routes_by_desirable_exit_nodes(&mut node_sequences);
    }

    #[test]
    #[should_panic(
        expected = "Unable to sort routes by desirable exit nodes: Missing route segments."
    )]
    fn sort_routes_by_desirable_exit_nodes_panics_with_the_second_route_segment_empty() {
        let subject = make_standard_subject();

        let mut node_sequences: Vec<Vec<&PublicKey>> = Vec::new();
        let public_key = &PublicKey::from(&b"1234"[..]);
        node_sequences.push(vec![public_key]);
        node_sequences.push(vec![]);

        subject.sort_routes_by_desirable_exit_nodes(&mut node_sequences);
    }

    #[test]
    #[should_panic(
        expected = "Unable to sort routes by desirable exit nodes: Missing NodeRecord for public key: [MTIzNA]"
    )]
    fn sort_routes_by_desirable_exit_nodes_panics_when_node_record_is_missing() {
        let subject = make_standard_subject();

        let mut node_sequences: Vec<Vec<&PublicKey>> = Vec::new();
        let public_key = &PublicKey::from(&b"1234"[..]);
        node_sequences.push(vec![public_key]);
        node_sequences.push(vec![public_key]);
        println!("{}", public_key);

        subject.sort_routes_by_desirable_exit_nodes(&mut node_sequences);
    }

    #[test]
    fn compose_route_query_response_returns_an_error_when_route_segment_is_empty() {
        let mut subject = make_standard_subject();

        let result: Result<RouteQueryResponse, String> = subject.compose_route_query_response(
            RouteSegment::new(vec![], Component::Neighborhood),
            RouteSegment::new(vec![], Component::Neighborhood),
        );
        assert!(result.is_err());
        let error_expectation: String = result.expect_err("Expected an Err but got:");
        assert_eq!(
            error_expectation,
            "Cannot make multi-hop route without segment keys"
        );
    }

    #[test]
    fn next_return_route_id_wraps_around() {
        let mut subject = make_standard_subject();
        subject.next_return_route_id = 0xFFFFFFFF;

        let end = subject.advance_return_route_id();
        let beginning = subject.advance_return_route_id();

        assert_eq!(end, 0xFFFFFFFF);
        assert_eq!(beginning, 0x00000000);
    }

    /*
            Database:

                 O---R---E

            Tests will be written from the viewpoint of O.
    */

    #[test]
    fn return_route_ids_increase() {
        let cryptde = cryptde();
        let system = System::new("return_route_ids_increase");
        let (_, _, _, subject) = make_o_r_e_subject();

        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let data_route_0 = sub.send(RouteQueryMessage::data_indefinite_route_request(2));
        let data_route_1 = sub.send(RouteQueryMessage::data_indefinite_route_request(2));

        System::current().stop_with_code(0);
        system.run();

        let result_0 = data_route_0.wait().unwrap().unwrap();
        let result_1 = data_route_1.wait().unwrap().unwrap();
        let juicy_parts = |result: RouteQueryResponse| {
            let last_element = result.route.hops.last().unwrap();
            let last_element_dec = cryptde.decode(last_element).unwrap();
            let network_return_route_id: u32 =
                serde_cbor::de::from_slice(last_element_dec.as_slice()).unwrap();
            let metadata_return_route_id = match result.expected_services {
                ExpectedServices::RoundTrip(_, _, id) => id,
                _ => panic!("expected RoundTrip got OneWay"),
            };
            (network_return_route_id, metadata_return_route_id)
        };
        assert_eq!(juicy_parts(result_0), (0, 0));
        assert_eq!(juicy_parts(result_1), (1, 1));
    }

    #[test]
    fn can_update_consuming_wallet() {
        let cryptde = cryptde();
        let system = System::new("can_update_consuming_wallet");
        let (o, r, e, subject) = make_o_r_e_subject();
        let addr: Addr<Neighborhood> = subject.start();
        let set_wallet_sub = addr.clone().recipient::<SetConsumingWalletMessage>();
        let route_sub = addr.recipient::<RouteQueryMessage>();
        let expected_new_wallet = make_paying_wallet(b"new consuming wallet");
        let expected_before_route = Route::round_trip(
            segment(&[&o, &r, &e], &Component::ProxyClient),
            segment(&[&e, &r, &o], &Component::ProxyServer),
            cryptde,
            Some(make_paying_wallet(b"consuming")),
            0,
            Some(contract_address(DEFAULT_CHAIN_ID)),
        )
        .unwrap();
        let expected_after_route = Route::round_trip(
            segment(&[&o, &r, &e], &Component::ProxyClient),
            segment(&[&e, &r, &o], &Component::ProxyServer),
            cryptde,
            Some(expected_new_wallet.clone()),
            1,
            Some(contract_address(DEFAULT_CHAIN_ID)),
        )
        .unwrap();

        let route_request_1 = route_sub.send(RouteQueryMessage::data_indefinite_route_request(2));
        let _ = set_wallet_sub.try_send(SetConsumingWalletMessage {
            wallet: expected_new_wallet,
        });
        let route_request_2 = route_sub.send(RouteQueryMessage::data_indefinite_route_request(2));

        System::current().stop();
        system.run();

        let route_1 = route_request_1.wait().unwrap().unwrap().route;
        let route_2 = route_request_2.wait().unwrap().unwrap().route;

        assert_eq!(route_1, expected_before_route);
        assert_eq!(route_2, expected_after_route);
    }

    #[test]
    fn compose_route_query_response_returns_an_error_when_route_segment_keys_is_empty() {
        let mut subject = make_standard_subject();

        let result: Result<RouteQueryResponse, String> = subject.compose_route_query_response(
            RouteSegment::new(vec![], Component::ProxyClient),
            RouteSegment::new(vec![], Component::ProxyServer),
        );
        assert!(result.is_err());
        let error_expectation: String = result.expect_err("Expected an Err but got:");
        assert_eq!(
            error_expectation,
            "Cannot make multi-hop route without segment keys"
        );
    }

    #[test]
    fn compose_route_query_response_returns_an_error_when_the_neighbor_is_none() {
        let mut subject = make_standard_subject();

        let result: Result<RouteQueryResponse, String> = subject.compose_route_query_response(
            RouteSegment::new(vec![&PublicKey::new(&[3, 3, 8])], Component::ProxyClient),
            RouteSegment::new(vec![&PublicKey::new(&[8, 3, 3])], Component::ProxyServer),
        );
        assert!(result.is_err());
        let error_expectation: String = result.expect_err("Expected an Err but got:");
        assert_eq!(
            error_expectation,
            "Cannot make multi_hop with unknown neighbor"
        );
        assert_eq!(subject.next_return_route_id, 0);
    }

    #[test]
    fn calculate_expected_service_returns_error_when_given_empty_segment() {
        let mut subject = make_standard_subject();
        let a = &make_node_record(3456, true);
        let db = &mut subject.neighborhood_database;
        db.add_node(a.clone()).unwrap();

        let result = subject.calculate_expected_service(a.public_key(), None, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "cannot calculate expected service, no keys provided in route segment"
        );
    }

    /*
            Database:

            Q---p---R
                |   |
            t---S---+

            p is consume-only, t is originate-only.
    */

    #[test]
    fn complete_routes_exercise() {
        let mut subject = make_standard_subject();
        let db = &mut subject.neighborhood_database;
        db.root_mut().inner.accepts_connections = false;
        db.root_mut().inner.routes_data = false;
        let p = &db.root_mut().public_key().clone(); // 9e7p7un06eHs6frl5A
        let q = &db.add_node(make_node_record(3456, true)).unwrap(); // AwQFBg
        let r = &db.add_node(make_node_record(4567, true)).unwrap(); // BAUGBw
        let s = &db.add_node(make_node_record(5678, true)).unwrap(); // BQYHCA
        let t = &db
            .add_node(make_node_record_f(6789, true, false, true))
            .unwrap(); // BgcICQ
        db.add_arbitrary_full_neighbor(q, p);
        db.add_arbitrary_full_neighbor(p, r);
        db.add_arbitrary_full_neighbor(p, s);
        db.add_arbitrary_full_neighbor(t, s);
        db.add_arbitrary_full_neighbor(s, r);

        let contains = |routes: &Vec<Vec<&PublicKey>>, expected_keys: Vec<&PublicKey>| {
            assert_contains(&routes, &expected_keys);
        };

        // At least two hops from p to anywhere standard
        let routes = subject.complete_routes(vec![p], None, 2, RouteDirection::Over);

        assert_eq!(routes, vec![vec![p, s, t]]);
        // no [p, r, s] or [p, s, r] because s and r are both neighbors of p and can't exit for it

        // At least two hops over from p to t
        let routes = subject.complete_routes(vec![p], Some(t), 2, RouteDirection::Over);

        contains(&routes, vec![p, s, t]);
        contains(&routes, vec![p, r, s, t]);
        assert_eq!(2, routes.len());

        // At least two hops over from t to p
        let routes = subject.complete_routes(vec![t], Some(p), 2, RouteDirection::Over);

        assert_eq!(routes, Vec::<Vec<&PublicKey>>::new());
        // p is consume-only; can't be an exit Node.

        // At least two hops back from t to p
        let routes = subject.complete_routes(vec![t], Some(p), 2, RouteDirection::Back);

        contains(&routes, vec![t, s, p]);
        contains(&routes, vec![t, s, r, p]);
        assert_eq!(2, routes.len());
        // p is consume-only, but it's the originating Node, so including it is okay

        // At least two hops from p to Q - impossible
        let routes = subject.complete_routes(vec![p], Some(q), 2, RouteDirection::Over);

        assert_eq!(routes, Vec::<Vec<&PublicKey>>::new());
    }

    /*
            Database:

            P---q---R

            Test is written from the standpoint of P. Node q is non-routing.
    */

    #[test]
    fn cant_route_through_non_routing_node() {
        let mut subject = make_standard_subject();
        let db = &mut subject.neighborhood_database;
        let p = &db.root_mut().public_key().clone(); // 9e7p7un06eHs6frl5A
        let q = &db
            .add_node(make_node_record_f(4567, true, false, false))
            .unwrap(); // BAUGBw
        let r = &db.add_node(make_node_record(5678, true)).unwrap(); // BQYHCA
        db.add_arbitrary_full_neighbor(p, q);
        db.add_arbitrary_full_neighbor(q, r);

        // At least two hops from P to anywhere standard
        let routes = subject.complete_routes(vec![p], None, 2, RouteDirection::Over);

        let expected: Vec<Vec<&PublicKey>> = vec![];
        assert_eq!(routes, expected);
    }

    #[test]
    fn gossips_after_removing_a_neighbor() {
        let (hopper, hopper_awaiter, hopper_recording) = make_recorder();
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            100,
            true,
            true,
        );
        let this_node_inside = this_node.clone();
        let removed_neighbor = make_node_record(2345, true);
        let removed_neighbor_inside = removed_neighbor.clone();
        let other_neighbor = make_node_record(3456, true);
        let other_neighbor_inside = other_neighbor.clone();

        thread::spawn(move || {
            let system = System::new("gossips_after_removing_a_neighbor");
            let mut subject = Neighborhood::new(
                cryptde,
                &bc_from_nc_plus(
                    NeighborhoodConfig {
                        mode: NeighborhoodMode::Standard(
                            this_node_inside.node_addr_opt().unwrap(),
                            vec![],
                            rate_pack(100),
                        ),
                    },
                    earning_wallet.clone(),
                    consuming_wallet.clone(),
                ),
            );
            let db = &mut subject.neighborhood_database;

            db.add_node(removed_neighbor_inside.clone()).unwrap();
            db.add_node(other_neighbor_inside.clone()).unwrap();
            db.add_arbitrary_full_neighbor(
                &cryptde.public_key(),
                removed_neighbor_inside.public_key(),
            );
            db.add_arbitrary_full_neighbor(
                &cryptde.public_key(),
                other_neighbor_inside.public_key(),
            );
            db.add_arbitrary_full_neighbor(
                removed_neighbor_inside.public_key(),
                other_neighbor_inside.public_key(),
            );

            let addr: Addr<Neighborhood> = subject.start();
            let peer_actors = peer_actors_builder().hopper(hopper).build();
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub: Recipient<RemoveNeighborMessage> = addr.recipient::<RemoveNeighborMessage>();
            sub.try_send(RemoveNeighborMessage {
                public_key: removed_neighbor_inside.public_key().clone(),
            })
            .unwrap();

            system.run();
        });

        let other_neighbor_cryptde =
            CryptDENull::from(other_neighbor.public_key(), DEFAULT_CHAIN_ID);
        hopper_awaiter.await_message_count(1);
        let locked_recording = hopper_recording.lock().unwrap();
        let package: &IncipientCoresPackage = locked_recording.get_record(0);
        let gossip = match decodex(&other_neighbor_cryptde, &package.payload).unwrap() {
            MessageType::Gossip(g) => g,
            x => panic!("Expected MessageType::Gossip, got {:?}", x),
        };
        type Digest = (PublicKey, Vec<u8>, bool, u32, Vec<PublicKey>);
        let to_actual_digest = |gnr: GossipNodeRecord| {
            let node_addr_opt = gnr.node_addr_opt.clone();
            let inner = NodeRecordInner::try_from(gnr).unwrap();
            let neighbors_vec = inner.neighbors.into_iter().collect::<Vec<PublicKey>>();
            (
                inner.public_key.clone(),
                inner.public_key.into(),
                node_addr_opt.is_some(),
                inner.version,
                neighbors_vec,
            )
        };

        let sort_digests = |digests: Vec<Digest>| {
            let mut digests = digests
                .into_iter()
                .map(|mut d| {
                    d.4.sort_unstable_by(|a, b| a.cmp(&b));
                    d
                })
                .collect_vec();
            digests.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            digests
        };

        let actual_digests = sort_digests(
            gossip
                .node_records
                .into_iter()
                .map(|gnr| to_actual_digest(gnr))
                .collect::<Vec<Digest>>(),
        );

        let expected_digests = sort_digests(vec![
            (
                removed_neighbor.public_key().clone(),
                removed_neighbor.public_key().clone().into(),
                false,
                0,
                vec![
                    other_neighbor.public_key().clone(),
                    this_node.public_key().clone(),
                ],
            ),
            (
                this_node.public_key().clone(),
                this_node.public_key().clone().into(),
                true,
                1,
                vec![other_neighbor.public_key().clone()],
            ),
        ]);

        assert_eq!(expected_digests, actual_digests);
    }

    #[test]
    fn neighborhood_calls_gossip_acceptor_when_gossip_is_received() {
        let handle_params_arc = Arc::new(Mutex::new(vec![]));
        let gossip_acceptor = GossipAcceptorMock::new()
            .handle_params(&handle_params_arc)
            .handle_result(GossipAcceptanceResult::Ignored);
        let subject_node = make_global_cryptde_node_record(1234, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1000, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let gossip = GossipBuilder::new(&subject.neighborhood_database)
            .node(subject_node.public_key(), true)
            .build();
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor: subject_node.node_addr_opt().unwrap().into(),
            paying_wallet: None,
            remaining_route: make_meaningless_route(),
            payload: gossip.clone(),
            payload_len: 0,
        };
        let system = System::new("");
        let addr: Addr<Neighborhood> = subject.start();
        let peer_actors = peer_actors_builder().build();
        addr.try_send(BindMessage { peer_actors }).unwrap();
        let sub = addr.recipient::<ExpiredCoresPackage<Gossip>>();

        sub.try_send(cores_package).unwrap();

        System::current().stop();
        system.run();
        let mut handle_params = handle_params_arc.lock().unwrap();
        let (call_database, call_agrs, call_gossip_source) = handle_params.remove(0);
        assert!(handle_params.is_empty());
        assert_eq!(&subject_node, call_database.root());
        assert_eq!(1, call_database.keys().len());
        let agrs: Vec<AccessibleGossipRecord> = gossip.try_into().unwrap();
        assert_eq!(agrs, call_agrs);
        let actual_gossip_source: SocketAddr = subject_node.node_addr_opt().unwrap().into();
        assert_eq!(actual_gossip_source, call_gossip_source);
    }

    #[test]
    fn neighborhood_sends_only_an_acceptance_debut_when_an_acceptance_debut_is_provided() {
        let introduction_target_node = make_node_record(7345, true);
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1000, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        subject
            .neighborhood_database
            .add_node(introduction_target_node.clone())
            .unwrap();

        subject.neighborhood_database.add_arbitrary_half_neighbor(
            subject_node.public_key(),
            introduction_target_node.public_key(),
        );
        let debut = GossipBuilder::new(&subject.neighborhood_database)
            .node(subject_node.public_key(), true)
            .build();
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Reply(
                debut.clone(),
                introduction_target_node.public_key().clone(),
                introduction_target_node.node_addr_opt().unwrap(),
            ));
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper_no_lookup = Some(peer_actors.hopper.from_hopper_client_no_lookup);

        subject.handle_gossip(
            Gossip::new(vec![]),
            SocketAddr::from_str("1.1.1.1:1111").unwrap(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<NoLookupIncipientCoresPackage>(0);
        assert_eq!(1, hopper_recording.len());
        assert_eq!(introduction_target_node.public_key(), &package.public_key);
        let gossip = match decodex::<MessageType>(
            &CryptDENull::from(introduction_target_node.public_key(), DEFAULT_CHAIN_ID),
            &package.payload,
        ) {
            Ok(MessageType::Gossip(g)) => g,
            x => panic!("Wanted Gossip, found {:?}", x),
        };
        assert_eq!(debut, gossip);
    }

    #[test]
    fn neighborhood_sends_from_gossip_producer_when_acceptance_introductions_are_not_provided() {
        init_test_logging();
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1000, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        let full_neighbor = make_node_record(1234, true);
        let half_neighbor = make_node_record(2345, true);
        subject
            .neighborhood_database
            .add_node(full_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(half_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(subject_node.public_key(), full_neighbor.public_key());
        subject
            .neighborhood_database
            .add_arbitrary_half_neighbor(subject_node.public_key(), half_neighbor.public_key());
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Accepted);
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let gossip = Gossip::new(vec![]);
        let produce_params_arc = Arc::new(Mutex::new(vec![]));
        let gossip_producer = GossipProducerMock::new()
            .produce_params(&produce_params_arc)
            .produce_result(gossip.clone())
            .produce_result(gossip.clone())
            .produce_result(gossip.clone());
        subject.gossip_producer = Box::new(gossip_producer);
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();

        let system = System::new("");
        subject.hopper = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_gossip(
            Gossip::new(vec![]),
            SocketAddr::from_str("1.1.1.1:1111").unwrap(),
        );

        System::current().stop();
        system.run();

        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package_1 = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let package_2 = hopper_recording.get_record::<IncipientCoresPackage>(1);
        fn digest(package: IncipientCoresPackage) -> (PublicKey, CryptData) {
            (
                package.route.next_hop(cryptde()).unwrap().public_key,
                package.payload,
            )
        }
        let digest_set = vec_to_set(vec![digest(package_1.clone()), digest(package_2.clone())]);
        assert_eq!(
            vec_to_set(vec![
                (
                    full_neighbor.public_key().clone(),
                    encodex(
                        cryptde(),
                        full_neighbor.public_key(),
                        &MessageType::Gossip(gossip.clone()),
                    )
                    .unwrap()
                ),
                (
                    half_neighbor.public_key().clone(),
                    encodex(
                        cryptde(),
                        half_neighbor.public_key(),
                        &MessageType::Gossip(gossip.clone()),
                    )
                    .unwrap()
                ),
            ]),
            digest_set
        );
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            format!(
                "INFO: Neighborhood: Sending update Gossip about 0 Nodes to Node {}",
                full_neighbor.public_key()
            )
            .as_str(),
        );
        tlh.exists_log_containing(
            format!(
                "INFO: Neighborhood: Sending update Gossip about 0 Nodes to Node {}",
                half_neighbor.public_key()
            )
            .as_str(),
        );
        let key_as_str = format!("{}", cryptde().public_key());
        tlh.exists_log_containing(&format!("Sent Gossip: digraph db {{ \"src\" [label=\"Gossip From:\\n{}\\n5.5.5.5\"]; \"dest\" [label=\"Gossip To:\\nAQIDBA\\n1.2.3.4\"]; \"src\" -> \"dest\" [arrowhead=empty]; }}", &key_as_str[..8]));
        tlh.exists_log_containing(&format!("Sent Gossip: digraph db {{ \"src\" [label=\"Gossip From:\\n{}\\n5.5.5.5\"]; \"dest\" [label=\"Gossip To:\\nAgMEBQ\\n2.3.4.5\"]; \"src\" -> \"dest\" [arrowhead=empty]; }}", &key_as_str[..8]));
    }

    #[test]
    fn neighborhood_sends_only_relay_gossip_when_gossip_acceptor_relays() {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let mut subject =
            neighborhood_from_nodes(&subject_node, Some(&make_node_record(1000, true)));
        let debut_node = make_node_record(1234, true);
        let debut_gossip = GossipBuilder::new(&subject.neighborhood_database)
            .node(subject_node.public_key(), true)
            .build();
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Reply(
                debut_gossip.clone(),
                debut_node.public_key().clone(),
                debut_node.node_addr_opt().unwrap(),
            ));
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper_no_lookup = Some(peer_actors.hopper.from_hopper_client_no_lookup);
        let gossip_source = SocketAddr::from_str("8.6.5.4:8654").unwrap();

        subject.handle_gossip(
            // In real life this would be Relay Gossip from gossip_source to debut_node.
            Gossip::new(vec![]),
            gossip_source,
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<NoLookupIncipientCoresPackage>(0);
        assert_eq!(1, hopper_recording.len());
        assert_eq!(debut_node.public_key(), &package.public_key);
        assert_eq!(
            debut_node.node_addr_opt().as_ref().unwrap(),
            &package.node_addr
        );
        assert_eq!(
            debut_gossip,
            match decodex::<MessageType>(
                &CryptDENull::from(debut_node.public_key(), DEFAULT_CHAIN_ID),
                &package.payload,
            ) {
                Ok(MessageType::Gossip(g)) => g,
                x => panic!("Expected Gossip, but found {:?}", x),
            },
        );
    }

    #[test]
    fn neighborhood_sends_no_gossip_when_gossip_acceptor_ignores() {
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1000, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Ignored);
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let subject_node = subject.neighborhood_database.root().clone();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_gossip(
            Gossip::new(vec![]),
            subject_node.node_addr_opt().unwrap().into(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(0, hopper_recording.len());
    }

    #[test]
    fn neighborhood_complains_about_inability_to_ban_when_gossip_acceptor_requests_it() {
        init_test_logging();
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let neighbor = make_node_record(1000, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&neighbor));
        let gossip_acceptor = GossipAcceptorMock::new()
            .handle_result(GossipAcceptanceResult::Ban("Bad guy".to_string()));
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let subject_node = subject.neighborhood_database.root().clone();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_gossip(
            Gossip::new(vec![]),
            subject_node.node_addr_opt().unwrap().into(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(0, hopper_recording.len());
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("WARN: Neighborhood: Malefactor detected at 5.5.5.5:5555, but malefactor bans not yet implemented; ignoring: Bad guy");
    }

    #[test]
    fn neighborhood_does_not_accept_gossip_if_a_record_is_non_deserializable() {
        init_test_logging();
        let mut subject = make_standard_subject();
        let gossip_acceptor = GossipAcceptorMock::new();
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let db = &mut subject.neighborhood_database;
        let one_node_key = &db.add_node(make_node_record(2222, true)).unwrap();
        let another_node_key = &db.add_node(make_node_record(3333, true)).unwrap();
        let mut gossip = GossipBuilder::new(db)
            .node(one_node_key, true)
            .node(another_node_key, false)
            .build();
        gossip.node_records[1].signed_data = PlainData::new(&[1, 2, 3, 4]); // corrupt second record
        let gossip_source = SocketAddr::from_str("1.2.3.4:1234").unwrap();

        subject.handle_gossip(gossip, gossip_source);

        // No panic means that subject didn't try to invoke the GossipAcceptorMock: test passes!
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Neighborhood: Received non-deserializable Gossip from {}",
            gossip_source
        ));
    }

    #[test]
    fn neighborhood_does_not_accept_gossip_if_a_record_signature_is_invalid() {
        init_test_logging();
        let mut subject = make_standard_subject();
        let gossip_acceptor = GossipAcceptorMock::new();
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let db = &mut subject.neighborhood_database;
        let one_node_key = &db.add_node(make_node_record(2222, true)).unwrap();
        let another_node_key = &db.add_node(make_node_record(3333, true)).unwrap();
        let mut gossip = GossipBuilder::new(db)
            .node(one_node_key, true)
            .node(another_node_key, false)
            .build();
        gossip.node_records[1].signature = CryptData::new(&[1, 2, 3, 4]); // corrupt second record
        let gossip_source = SocketAddr::from_str("1.2.3.4:1234").unwrap();

        subject.handle_gossip(gossip, gossip_source);

        // No panic means that subject didn't try to invoke the GossipAcceptorMock: test passes!
        TestLogHandler::new().exists_log_containing(&format!(
            "ERROR: Neighborhood: Received Gossip with invalid signature from {}",
            gossip_source
        ));
    }

    #[test]
    fn neighborhood_logs_received_gossip_in_dot_graph_format() {
        init_test_logging();
        let cryptde = cryptde();
        let this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            100,
            true,
            true,
        );
        let mut db = db_from_node(&this_node);
        let far_neighbor = make_node_record(1324, true);
        let gossip_neighbor = make_node_record(4657, true);
        db.add_node(far_neighbor.clone()).unwrap();
        db.add_node(gossip_neighbor.clone()).unwrap();
        db.add_arbitrary_full_neighbor(this_node.public_key(), gossip_neighbor.public_key());
        db.add_arbitrary_full_neighbor(gossip_neighbor.public_key(), far_neighbor.public_key());
        db.node_by_key_mut(this_node.public_key()).unwrap().resign();
        db.node_by_key_mut(gossip_neighbor.public_key())
            .unwrap()
            .resign();
        db.node_by_key_mut(far_neighbor.public_key())
            .unwrap()
            .resign();

        let gossip = GossipBuilder::new(&db)
            .node(gossip_neighbor.public_key(), true)
            .node(far_neighbor.public_key(), false)
            .build();
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor: SocketAddr::from_str("1.2.3.4:1234").unwrap(),
            paying_wallet: Some(make_paying_wallet(b"consuming")),
            remaining_route: make_meaningless_route(),
            payload: gossip,
            payload_len: 0,
        };
        let hopper = Recorder::new();
        let this_node_inside = this_node.clone();
        thread::spawn(move || {
            let system = System::new("");
            let subject = Neighborhood::new(
                cryptde,
                &bc_from_nc_plus(
                    NeighborhoodConfig {
                        mode: NeighborhoodMode::Standard(
                            this_node_inside.node_addr_opt().unwrap(),
                            vec![],
                            rate_pack(100),
                        ),
                    },
                    this_node_inside.earning_wallet(),
                    None,
                ),
            );

            let addr: Addr<Neighborhood> = subject.start();
            let peer_actors = peer_actors_builder().hopper(hopper).build();
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub = addr.recipient::<ExpiredCoresPackage<Gossip>>();
            sub.try_send(cores_package).unwrap();

            system.run();
        });
        let tlh = TestLogHandler::new();
        tlh.await_log_containing(
            &format!("\"BAYFBw\" [label=\"AR v0\\nBAYFBw\\n4.6.5.7:4657\"];"),
            5000,
        );

        tlh.exists_log_containing("Received Gossip: digraph db { ");
        tlh.exists_log_containing("\"AQMCBA\" [label=\"AR v0\\nAQMCBA\"];");
        tlh.exists_log_containing(&format!(
            "\"{}\" [label=\"{}\"] [shape=none];",
            cryptde.public_key(),
            &format!("{}", cryptde.public_key())[..8]
        ));
        tlh.exists_log_containing(&format!("\"BAYFBw\" -> \"{}\";", cryptde.public_key()));
        tlh.exists_log_containing("\"AQMCBA\" -> \"BAYFBw\";");
        tlh.exists_log_containing("\"BAYFBw\" -> \"AQMCBA\";");
    }

    #[test]
    fn node_gossips_to_neighbors_on_startup() {
        let cryptde = cryptde();
        let neighbor = make_node_record(1234, true);
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let hopper_recording = hopper.get_recording();
        let neighbor_inside = neighbor.clone();
        let subject = Neighborhood::new(
            cryptde,
            &bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![1234]),
                        vec![NodeDescriptor::from(&neighbor_inside)
                            .to_string(cryptde, DEFAULT_CHAIN_ID)],
                        rate_pack(100),
                    ),
                },
                NodeRecord::earning_wallet_from_key(&cryptde.public_key()),
                NodeRecord::consuming_wallet_from_key(&cryptde.public_key()),
            ),
        );
        let this_node = subject.neighborhood_database.root().clone();
        thread::spawn(move || {
            let system = System::new("node_gossips_to_neighbors_on_startup");
            let addr: Addr<Neighborhood> = subject.start();
            let peer_actors = peer_actors_builder().hopper(hopper).build();
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub = addr.recipient::<StartMessage>();

            sub.try_send(StartMessage {}).unwrap();

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let locked_recording = hopper_recording.lock().unwrap();
        let package_ref: &NoLookupIncipientCoresPackage = locked_recording.get_record(0);
        let neighbor_node_cryptde = CryptDENull::from(neighbor.public_key(), DEFAULT_CHAIN_ID);
        let decrypted_payload = neighbor_node_cryptde.decode(&package_ref.payload).unwrap();
        let gossip = match serde_cbor::de::from_slice(decrypted_payload.as_slice()).unwrap() {
            MessageType::Gossip(g) => g,
            x => panic!("Should have been MessageType::Gossip, but was {:?}", x),
        };
        let temp_db = db_from_node(&this_node);
        let expected_gnr = GossipNodeRecord::from((&temp_db, this_node.public_key(), true));
        assert_contains(&gossip.node_records, &expected_gnr);
        assert_eq!(1, gossip.node_records.len());
    }

    /*
            Database, where we'll fail to make a three-hop route to C after removing A:

                 NN--------+
                 NN        |
                 |         |
                 v         v
                 AA-->BB-->CC
                 AA<--BB<--CC

                 after removing A as neighbor...

                 NN--------+
                 NN        |
                           |
                           v
                 AA-->BB-->CC
                 AA<--BB<--CC

            Tests will be written from the viewpoint of N.
    */

    #[test]
    fn neighborhood_removes_neighbor_when_directed_to() {
        let system = System::new("neighborhood_removes_neighbor_when_directed_to");
        let hopper = Recorder::new();
        let mut subject = make_standard_subject();
        let n = &subject.neighborhood_database.root().clone();
        let a = &make_node_record(3456, true);
        let b = &make_node_record(4567, false);
        let c = &make_node_record(5678, true);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(a.clone()).unwrap();
            db.add_node(b.clone()).unwrap();
            db.add_node(c.clone()).unwrap();
            let mut single_edge = |a: &NodeRecord, b: &NodeRecord| {
                db.add_arbitrary_half_neighbor(a.public_key(), b.public_key())
            };
            single_edge(n, a);
            single_edge(n, c);
            single_edge(a, b);
            single_edge(b, a);
            single_edge(b, c);
            single_edge(c, b);
        }

        let addr: Addr<Neighborhood> = subject.start();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        addr.try_send(BindMessage { peer_actors }).unwrap();

        addr.try_send(RemoveNeighborMessage {
            public_key: a.public_key().clone(),
        })
        .unwrap();

        let three_hop_route_request = RouteQueryMessage {
            target_key_opt: Some(c.public_key().clone()),
            target_component: Component::ProxyClient,
            minimum_hop_count: 3,
            return_component_opt: None,
        };
        let unsuccessful_three_hop_route = addr.send(three_hop_route_request);
        let public_key_query = addr.send(NodeQueryMessage::PublicKey(a.public_key().clone()));
        let failed_ip_address_query = addr.send(NodeQueryMessage::IpAddress(
            a.node_addr_opt().unwrap().ip_addr(),
        ));
        System::current().stop_with_code(0);

        system.run();
        assert_eq!(None, unsuccessful_three_hop_route.wait().unwrap());
        assert_eq!(
            a.public_key(),
            &public_key_query.wait().unwrap().unwrap().public_key
        );
        assert_eq!(None, failed_ip_address_query.wait().unwrap());
    }

    fn node_record_to_neighbor_config(
        node_record_ref: &NodeRecord,
        cryptde: &dyn CryptDE,
    ) -> String {
        NodeDescriptor::from((
            &node_record_ref.public_key().clone(),
            &node_record_ref.node_addr_opt().unwrap().clone(),
        ))
        .to_string(cryptde, DEFAULT_CHAIN_ID)
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_none_when_initially_configured_with_no_data() {
        let cryptde = cryptde();
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("responds_with_none_when_initially_configured_with_no_data");

            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();

            let subject = make_standard_subject();
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::PublicKey(PublicKey::new(&b"booga"[..])),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(cryptde.public_key().clone()),
                    last_data: false,
                    sequence_number: None,
                    data: Vec::new(),
                },
                recipient,
            })
            .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 1);
        let message = recording.get_record::<DispatcherNodeQueryResponse>(0);
        assert_eq!(message.result, None);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_none_when_key_query_matches_no_configured_data()
    {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("neighborhood_sends_node_query_response_with_none_when_key_query_matches_no_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();

            let subject = Neighborhood::new(
                cryptde,
                &bc_from_nc_plus(
                    NeighborhoodConfig {
                        mode: NeighborhoodMode::Standard(
                            NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]),
                            vec![NodeDescriptor::from((
                                &PublicKey::new(&b"booga"[..]),
                                &NodeAddr::new(
                                    &IpAddr::from_str("1.2.3.4").unwrap(),
                                    &vec![1234, 2345],
                                ),
                            ))
                            .to_string(cryptde, DEFAULT_CHAIN_ID)],
                            rate_pack(100),
                        ),
                    },
                    earning_wallet.clone(),
                    consuming_wallet.clone(),
                ),
            );
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::PublicKey(PublicKey::new(&b"blah"[..])),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(cryptde.public_key().clone()),
                    last_data: false,
                    sequence_number: None,
                    data: Vec::new(),
                },
                recipient,
            })
            .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 1);
        let message = recording.get_record::<DispatcherNodeQueryResponse>(0);
        assert_eq!(message.result, None);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_result_when_key_query_matches_configured_data() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        let one_neighbor = make_node_record(2345, true);
        let another_neighbor = make_node_record(3456, true);
        let another_neighbor_a = another_neighbor.clone();
        let context = TransmitDataMsg {
            endpoint: Endpoint::Key(cryptde.public_key().clone()),
            last_data: false,
            sequence_number: None,
            data: Vec::new(),
        };
        let context_a = context.clone();
        thread::spawn(move || {
            let system = System::new("neighborhood_sends_node_query_response_with_result_when_key_query_matches_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient = addr.recipient::<DispatcherNodeQueryResponse>();
            let mut subject = Neighborhood::new(
                cryptde,
                &bc_from_nc_plus(
                    NeighborhoodConfig {
                        mode: NeighborhoodMode::Standard(
                            NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]),
                            vec![node_record_to_neighbor_config(&one_neighbor, cryptde)],
                            rate_pack(100),
                        ),
                    },
                    earning_wallet.clone(),
                    consuming_wallet.clone(),
                ),
            );
            subject
                .neighborhood_database
                .add_node(another_neighbor.clone())
                .unwrap();
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::PublicKey(another_neighbor.public_key().clone()),
                context,
                recipient,
            })
            .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let message = Recording::get::<DispatcherNodeQueryResponse>(&recording_arc, 0);
        assert_eq!(
            message.result.unwrap(),
            NodeQueryResponseMetadata::new(
                another_neighbor_a.public_key().clone(),
                Some(another_neighbor_a.node_addr_opt().unwrap().clone()),
                another_neighbor_a.rate_pack().clone(),
            )
        );
        assert_eq!(message.context, context_a);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_none_when_ip_address_query_matches_no_configured_data(
    ) {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_paying_wallet(b"consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("neighborhood_sends_node_query_response_with_none_when_ip_address_query_matches_no_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();
            let subject = Neighborhood::new(
                cryptde,
                &bc_from_nc_plus(
                    NeighborhoodConfig {
                        mode: NeighborhoodMode::Standard(
                            NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]),
                            vec![NodeDescriptor::from((
                                &PublicKey::new(&b"booga"[..]),
                                &NodeAddr::new(
                                    &IpAddr::from_str("1.2.3.4").unwrap(),
                                    &vec![1234, 2345],
                                ),
                            ))
                            .to_string(cryptde, DEFAULT_CHAIN_ID)],
                            rate_pack(100),
                        ),
                    },
                    earning_wallet.clone(),
                    consuming_wallet.clone(),
                ),
            );
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::IpAddress(IpAddr::from_str("2.3.4.5").unwrap()),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(cryptde.public_key().clone()),
                    last_data: false,
                    sequence_number: None,
                    data: Vec::new(),
                },
                recipient,
            })
            .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 1);
        let message = recording.get_record::<DispatcherNodeQueryResponse>(0);
        assert_eq!(message.result, None);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_result_when_ip_address_query_matches_configured_data(
    ) {
        let cryptde = cryptde();
        let (recorder, awaiter, recording_arc) = make_recorder();
        let node_record = make_node_record(1234, true);
        let another_node_record = make_node_record(2345, true);
        let another_node_record_a = another_node_record.clone();
        let context = TransmitDataMsg {
            endpoint: Endpoint::Key(cryptde.public_key().clone()),
            last_data: false,
            sequence_number: None,
            data: Vec::new(),
        };
        let context_a = context.clone();
        thread::spawn(move || {
            let system = System::new("neighborhood_sends_node_query_response_with_result_when_ip_address_query_matches_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();
            let config = bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        node_record.node_addr_opt().unwrap(),
                        vec![
                            NodeDescriptor::from(&node_record).to_string(cryptde, DEFAULT_CHAIN_ID)
                        ],
                        rate_pack(100),
                    ),
                },
                node_record.earning_wallet(),
                None,
            );
            let mut subject = Neighborhood::new(cryptde, &config);
            subject
                .neighborhood_database
                .add_node(another_node_record_a)
                .unwrap();
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::IpAddress(IpAddr::from_str("2.3.4.5").unwrap()),
                context,
                recipient,
            })
            .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let message = Recording::get::<DispatcherNodeQueryResponse>(&recording_arc, 0);

        assert_eq!(
            message.result.unwrap(),
            NodeQueryResponseMetadata::new(
                another_node_record.public_key().clone(),
                Some(another_node_record.node_addr_opt().unwrap().clone()),
                another_node_record.rate_pack().clone(),
            )
        );
        assert_eq!(message.context, context_a);
    }

    #[test]
    fn neighborhood_responds_with_dot_graph_when_requested_and_logs_acknowledgement() {
        init_test_logging();
        let cryptde = cryptde();

        let (recorder, awaiter, recording_arc) = make_recorder();
        let node_record = make_node_record(1234, true);
        let another_node_record = make_node_record(2345, true);
        let another_node_record_a = another_node_record.clone();

        thread::spawn(move || {
            let system = System::new("neighborhood_responds_with_dot_graph_when_requested");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<UiCarrierMessage> = addr.recipient::<UiCarrierMessage>();
            let config = bc_from_nc_plus(
                NeighborhoodConfig {
                    mode: NeighborhoodMode::Standard(
                        node_record.node_addr_opt().unwrap(),
                        vec![
                            NodeDescriptor::from(&node_record).to_string(cryptde, DEFAULT_CHAIN_ID)
                        ],
                        rate_pack(100),
                    ),
                },
                node_record.earning_wallet(),
                None,
            );
            let mut subject = Neighborhood::new(cryptde, &config);
            subject.dot_graph_recipient = Some(recipient);
            subject
                .neighborhood_database
                .add_node(another_node_record_a)
                .unwrap();
            let addr: Addr<Neighborhood> = subject.start();
            let sub: Recipient<NeighborhoodDotGraphRequest> =
                addr.recipient::<NeighborhoodDotGraphRequest>();

            sub.try_send(NeighborhoodDotGraphRequest { client_id: 0 })
                .unwrap();

            system.run();
        });

        awaiter.await_message_count(1);

        let ui_gateway_recording = recording_arc.lock().unwrap();
        let response = ui_gateway_recording.get_record::<UiCarrierMessage>(0);
        match &response.data {
            UiMessage::NeighborhoodDotGraphResponse(s) => {
                assert_matches(s.as_str(), r#"digraph db . ".*" .*; ".*" .*; ."#)
            }
            _ => assert!(false, "Failed to match "),
        }

        TestLogHandler::new().exists_log_containing(
            "INFO: Neighborhood: acknowledge request for neighborhood dot graph.",
        );
    }

    #[test]
    fn make_round_trip_route_returns_error_when_no_non_next_door_neighbor_found() {
        // Make a triangle of Nodes
        let one_next_door_neighbor = make_node_record(3, true);
        let another_next_door_neighbor = make_node_record(4, true);
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&one_next_door_neighbor));

        subject
            .neighborhood_database
            .add_node(one_next_door_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(another_next_door_neighbor.clone())
            .unwrap();

        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            one_next_door_neighbor.public_key(),
        );
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            another_next_door_neighbor.public_key(),
        );
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            one_next_door_neighbor.public_key(),
            another_next_door_neighbor.public_key(),
        );

        let minimum_hop_count = 2;

        let result = subject.make_round_trip_route(RouteQueryMessage {
            target_key_opt: None,
            target_component: Component::ProxyClient,
            minimum_hop_count,
            return_component_opt: Some(Component::ProxyServer),
        });

        assert_eq!(
            Err(format!(
                "Couldn't find any routes: at least {}-hop from {} to ProxyClient at Unknown",
                minimum_hop_count,
                cryptde().public_key()
            )),
            result
        );
    }

    #[test]
    fn make_round_trip_succeeds_when_it_finds_non_next_door_neighbor_exit_node() {
        let next_door_neighbor = make_node_record(3, true);
        let exit_node = make_node_record(5, false);

        let subject_node = make_global_cryptde_node_record(666, true); // 9e7p7un06eHs6frl5A
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&next_door_neighbor));

        subject
            .neighborhood_database
            .add_node(next_door_neighbor.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(exit_node.clone())
            .unwrap();

        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            next_door_neighbor.public_key(),
        );

        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(next_door_neighbor.public_key(), exit_node.public_key());

        let minimum_hop_count = 2;

        let result = subject.make_round_trip_route(RouteQueryMessage {
            target_key_opt: None,
            target_component: Component::ProxyClient,
            minimum_hop_count,
            return_component_opt: Some(Component::ProxyServer),
        });

        let next_door_neighbor_cryptde =
            CryptDENull::from(&next_door_neighbor.public_key(), DEFAULT_CHAIN_ID);
        let exit_node_cryptde = CryptDENull::from(&exit_node.public_key(), DEFAULT_CHAIN_ID);

        let hops = result.clone().unwrap().route.hops;
        let actual_keys: Vec<PublicKey> = match hops.as_slice() {
            [hop, exit, hop_back, origin, empty, _accounting] => vec![
                decodex::<LiveHop>(cryptde(), hop).expect("hop").public_key,
                decodex::<LiveHop>(&next_door_neighbor_cryptde, exit)
                    .expect("exit")
                    .public_key,
                decodex::<LiveHop>(&exit_node_cryptde, hop_back)
                    .expect("hop_back")
                    .public_key,
                decodex::<LiveHop>(&next_door_neighbor_cryptde, origin)
                    .expect("origin")
                    .public_key,
                decodex::<LiveHop>(cryptde(), empty)
                    .expect("empty")
                    .public_key,
            ],
            l => panic!("our match is wrong, real size is {}, {:?}", l.len(), l),
        };
        let expected_public_keys = vec![
            next_door_neighbor.public_key().clone(),
            exit_node.public_key().clone(),
            next_door_neighbor.public_key().clone(),
            subject_node.public_key().clone(),
            PublicKey::new(b""),
        ];
        assert_eq!(expected_public_keys, actual_keys);
    }

    #[test]
    #[should_panic(
        expected = "Neighborhood should never get ShutdownStreamMsg about non-clandestine stream"
    )]
    fn handle_stream_shutdown_complains_about_non_clandestine_message() {
        let subject_node = make_global_cryptde_node_record(1345, true);
        let mut subject = neighborhood_from_nodes(&subject_node, None);

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: SocketAddr::from_str("1.2.3.4:5678").unwrap(),
            stream_type: RemovedStreamType::NonClandestine(NonClandestineAttributes {
                reception_port: TLS_PORT,
                sequence_number: 1234,
            }),
            report_to_counterpart: false,
        });
    }

    #[test]
    fn handle_stream_shutdown_handles_socket_addr_with_unknown_ip() {
        init_test_logging();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let system = System::new("test");
        let unrecognized_node = make_node_record(3123, true);
        let unrecognized_node_addr = unrecognized_node.node_addr_opt().unwrap();
        let unrecognized_socket_addr = SocketAddr::new(
            unrecognized_node_addr.ip_addr(),
            unrecognized_node_addr.ports()[0],
        );
        let subject_node = make_global_cryptde_node_record(1345, true);
        let mut subject = neighborhood_from_nodes(&subject_node, None);
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        subject.hopper = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: unrecognized_socket_addr,
            stream_type: RemovedStreamType::Clandestine,
            report_to_counterpart: true,
        });

        System::current().stop_with_code(0);
        system.run();

        assert_eq!(subject.neighborhood_database.keys().len(), 1);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(&format!("WARN: Neighborhood: Received shutdown notification for stream to {}, but no Node with that IP is in the database - ignoring", unrecognized_socket_addr.ip()));
    }

    #[test]
    fn handle_stream_shutdown_handles_already_inactive_node() {
        init_test_logging();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let system = System::new("test");
        let gossip_neighbor_node = make_node_record(2456, true);
        let inactive_neighbor_node = make_node_record(3123, true);
        let inactive_neighbor_node_addr = inactive_neighbor_node.node_addr_opt().unwrap();
        let inactive_neighbor_node_socket_addr = SocketAddr::new(
            inactive_neighbor_node_addr.ip_addr(),
            inactive_neighbor_node_addr.ports()[0],
        );
        let subject_node = make_global_cryptde_node_record(1345, true);
        let mut subject = neighborhood_from_nodes(&subject_node, None);
        subject
            .neighborhood_database
            .add_node(gossip_neighbor_node.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(inactive_neighbor_node.clone())
            .unwrap();
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            gossip_neighbor_node.public_key(),
        );
        subject.neighborhood_database.add_arbitrary_half_neighbor(
            inactive_neighbor_node.public_key(),
            subject_node.public_key(),
        );
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        subject.hopper = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: inactive_neighbor_node_socket_addr,
            stream_type: RemovedStreamType::Clandestine,
            report_to_counterpart: true,
        });

        System::current().stop_with_code(0);
        system.run();

        assert_eq!(subject.neighborhood_database.keys().len(), 3);
        assert_eq!(
            subject.neighborhood_database.has_half_neighbor(
                subject_node.public_key(),
                inactive_neighbor_node.public_key(),
            ),
            false
        );
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
        TestLogHandler::new().exists_log_containing(&format!("DEBUG: Neighborhood: Received shutdown notification for {} at {}, but that Node is no neighbor - ignoring", inactive_neighbor_node.public_key(), inactive_neighbor_node_socket_addr.ip()));
    }

    #[test]
    fn handle_stream_shutdown_handles_existing_socket_addr() {
        init_test_logging();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let system = System::new("test");
        let gossip_neighbor_node = make_node_record(2456, true);
        let shutdown_neighbor_node = make_node_record(3123, true);
        let shutdown_neighbor_node_addr = shutdown_neighbor_node.node_addr_opt().unwrap();
        let shutdown_neighbor_node_socket_addr = SocketAddr::new(
            shutdown_neighbor_node_addr.ip_addr(),
            shutdown_neighbor_node_addr.ports()[0],
        );
        let subject_node = make_global_cryptde_node_record(1345, true);
        let mut subject = neighborhood_from_nodes(&subject_node, None);
        subject
            .neighborhood_database
            .add_node(gossip_neighbor_node.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_node(shutdown_neighbor_node.clone())
            .unwrap();
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            gossip_neighbor_node.public_key(),
        );
        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            shutdown_neighbor_node.public_key(),
        );
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        subject.hopper = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: shutdown_neighbor_node_socket_addr,
            stream_type: RemovedStreamType::Clandestine,
            report_to_counterpart: true,
        });

        System::current().stop_with_code(0);
        system.run();

        assert_eq!(subject.neighborhood_database.keys().len(), 3);
        assert_eq!(
            subject.neighborhood_database.has_half_neighbor(
                subject_node.public_key(),
                shutdown_neighbor_node.public_key(),
            ),
            false
        );
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 1);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: Neighborhood: Received shutdown notification for {} at {}: removing neighborship",
            shutdown_neighbor_node.public_key(),
            shutdown_neighbor_node_socket_addr.ip()
        ));
    }

    fn make_standard_subject() -> Neighborhood {
        let root_node = make_global_cryptde_node_record(9999, true);
        let neighbor_node = make_node_record(9998, true);
        neighborhood_from_nodes(&root_node, Some(&neighbor_node))
    }

    fn make_o_r_e_subject() -> (NodeRecord, NodeRecord, NodeRecord, Neighborhood) {
        let mut subject = make_standard_subject();
        let o = &subject.neighborhood_database.root().clone();
        let r = &make_node_record(4567, false);
        let e = &make_node_record(5678, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(r.clone()).unwrap();
            db.add_node(e.clone()).unwrap();
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| {
                db.add_arbitrary_full_neighbor(a.public_key(), b.public_key())
            };
            dual_edge(o, r);
            dual_edge(r, e);
        }
        (o.clone(), r.clone(), e.clone(), subject)
    }

    fn segment(nodes: &[&NodeRecord], component: &Component) -> RouteSegment {
        RouteSegment::new(
            nodes.into_iter().map(|n| n.public_key()).collect(),
            component.clone(),
        )
    }

    pub struct GossipAcceptorMock {
        handle_params: Arc<
            Mutex<
                Vec<(
                    NeighborhoodDatabase,
                    Vec<AccessibleGossipRecord>,
                    SocketAddr,
                )>,
            >,
        >,
        handle_results: RefCell<Vec<GossipAcceptanceResult>>,
    }

    impl GossipAcceptor for GossipAcceptorMock {
        fn handle(
            &self,
            database: &mut NeighborhoodDatabase,
            agrs: Vec<AccessibleGossipRecord>,
            gossip_source: SocketAddr,
        ) -> GossipAcceptanceResult {
            self.handle_params
                .lock()
                .unwrap()
                .push((database.clone(), agrs, gossip_source));
            self.handle_results.borrow_mut().remove(0)
        }
    }

    impl GossipAcceptorMock {
        pub fn new() -> GossipAcceptorMock {
            GossipAcceptorMock {
                handle_params: Arc::new(Mutex::new(vec![])),
                handle_results: RefCell::new(vec![]),
            }
        }

        pub fn handle_params(
            mut self,
            params_arc: &Arc<
                Mutex<
                    Vec<(
                        NeighborhoodDatabase,
                        Vec<AccessibleGossipRecord>,
                        SocketAddr,
                    )>,
                >,
            >,
        ) -> GossipAcceptorMock {
            self.handle_params = params_arc.clone();
            self
        }

        pub fn handle_result(self, result: GossipAcceptanceResult) -> GossipAcceptorMock {
            self.handle_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Default)]
    pub struct GossipProducerMock {
        produce_params: Arc<Mutex<Vec<(NeighborhoodDatabase, PublicKey)>>>,
        produce_results: RefCell<Vec<Gossip>>,
    }

    impl GossipProducer for GossipProducerMock {
        fn produce(&self, database: &NeighborhoodDatabase, target: &PublicKey) -> Gossip {
            self.produce_params
                .lock()
                .unwrap()
                .push((database.clone(), target.clone()));
            self.produce_results.borrow_mut().remove(0)
        }

        fn produce_debut(&self, _database: &NeighborhoodDatabase) -> Gossip {
            unimplemented!()
        }
    }

    impl GossipProducerMock {
        pub fn new() -> GossipProducerMock {
            Self::default()
        }

        pub fn produce_params(
            mut self,
            params_arc: &Arc<Mutex<Vec<(NeighborhoodDatabase, PublicKey)>>>,
        ) -> GossipProducerMock {
            self.produce_params = params_arc.clone();
            self
        }

        pub fn produce_result(self, result: Gossip) -> GossipProducerMock {
            self.produce_results.borrow_mut().push(result);
            self
        }
    }

    fn bc_from_nc_plus(
        nc: NeighborhoodConfig,
        earning_wallet: Wallet,
        consuming_wallet_opt: Option<Wallet>,
    ) -> BootstrapperConfig {
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config = nc;
        config.earning_wallet = earning_wallet;
        config.consuming_wallet = consuming_wallet_opt;
        config
    }

    pub struct NeighborhoodDatabaseMessage {}

    impl Message for NeighborhoodDatabaseMessage {
        type Result = NeighborhoodDatabase;
    }

    impl<A, M> MessageResponse<A, M> for NeighborhoodDatabase
    where
        A: Actor,
        M: Message<Result = NeighborhoodDatabase>,
    {
        fn handle<R: ResponseChannel<M>>(self, _: &mut A::Context, tx: Option<R>) {
            if let Some(tx) = tx {
                tx.send(self);
            }
        }
    }

    impl Handler<NeighborhoodDatabaseMessage> for Neighborhood {
        type Result = NeighborhoodDatabase;

        fn handle(
            &mut self,
            _msg: NeighborhoodDatabaseMessage,
            _ctx: &mut Self::Context,
        ) -> Self::Result {
            self.neighborhood_database.clone()
        }
    }
}
