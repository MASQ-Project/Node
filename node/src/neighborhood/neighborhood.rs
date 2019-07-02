// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::gossip_acceptor::GossipAcceptor;
use super::gossip_acceptor::GossipAcceptorReal;
use super::gossip_producer::GossipProducer;
use super::gossip_producer::GossipProducerReal;
use super::neighborhood_database::NeighborhoodDatabase;
use super::node_record::NodeRecord;
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
use crate::sub_lib::neighborhood::NeighborhoodConfig;
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::neighborhood::NodeQueryMessage;
use crate::sub_lib::neighborhood::NodeQueryResponseMetadata;
use crate::sub_lib::neighborhood::RemoveNeighborMessage;
use crate::sub_lib::neighborhood::RouteQueryMessage;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::neighborhood::{sentinel_ip_addr, NodeRecordMetadataMessage};
use crate::sub_lib::neighborhood::{BootstrapNeighborhoodNowMessage, NodeDescriptor};
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::route::Route;
use crate::sub_lib::route::RouteSegment;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::utils::regenerate_signed_gossip;
use crate::sub_lib::utils::NODE_MAILBOX_CAPACITY;
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MessageResult;
use actix::Recipient;
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::net::IpAddr;

pub struct Neighborhood {
    cryptde: &'static dyn CryptDE,
    hopper: Option<Recipient<IncipientCoresPackage>>,
    hopper_no_lookup: Option<Recipient<NoLookupIncipientCoresPackage>>,
    gossip_acceptor: Box<dyn GossipAcceptor>,
    gossip_producer: Box<dyn GossipProducer>,
    neighborhood_database: NeighborhoodDatabase,
    consuming_wallet_opt: Option<Wallet>,
    next_return_route_id: u32,
    initial_neighbors: Vec<String>,
    logger: Logger,
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
    }
}

impl Handler<BootstrapNeighborhoodNowMessage> for Neighborhood {
    type Result = ();

    fn handle(
        &mut self,
        _msg: BootstrapNeighborhoodNowMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        if self.initial_neighbors.is_empty() {
            info!(self.logger, format!("No Nodes to report to; continuing"));
            return;
        }

        let gossip = self
            .gossip_producer
            .produce_debut(&self.neighborhood_database);
        &self.initial_neighbors.iter().for_each(|neighbor| {
            let node_descriptor = match NodeDescriptor::from_str(self.cryptde, neighbor) {
                Ok(nd) => nd,
                Err(e) => panic!(
                    "--neighbors must be <public key>:<ip address>:<port>;<port>..., not '{}'",
                    e
                ),
            };
            self.hopper_no_lookup
                .as_ref()
                .expect("unbound hopper")
                .try_send(
                    NoLookupIncipientCoresPackage::new(
                        self.cryptde,
                        &node_descriptor.public_key,
                        &node_descriptor.node_addr,
                        MessageType::Gossip(gossip.clone()),
                    )
                    .expect("Key magically disappeared"),
                )
                .expect("hopper is dead");
            trace!(
                self.logger,
                format!(
                    "Sent Gossip: {}",
                    gossip.to_dot_graph(
                        self.neighborhood_database.root(),
                        (
                            &node_descriptor.public_key,
                            &Some(node_descriptor.node_addr.clone())
                        )
                    )
                )
            );
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
                    format!("Processed {} into {:?}", msg_str, response.clone())
                );
                Some(response)
            }
            Err(msg) => {
                error!(self.logger, format!("Unsatisfied route query: {}", msg));
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
        self.log_incoming_gossip(&incoming_gossip, msg.immediate_neighbor_ip);
        self.handle_gossip(incoming_gossip, msg.immediate_neighbor_ip);
    }
}

impl Handler<RemoveNeighborMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: RemoveNeighborMessage, _ctx: &mut Self::Context) -> Self::Result {
        let public_key = &msg.public_key;
        match self.neighborhood_database.remove_neighbor(public_key) {
            Err(s) => error!(self.logger, s),
            Ok(db_changed) => {
                if db_changed {
                    self.gossip_to_neighbors();
                    info!(
                        self.logger,
                        format!("removed neighbor by public key: {}", public_key)
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

#[derive(Debug, PartialEq, Clone)]
pub struct AccessibleGossipRecord {
    pub signed_gossip: PlainData,
    pub signature: CryptData,
    pub node_addr_opt: Option<NodeAddr>,
    pub inner: NodeRecordInner,
}

impl AccessibleGossipRecord {
    pub fn regenerate_signed_gossip(&mut self, cryptde: &CryptDE) {
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

impl Neighborhood {
    pub fn new(cryptde: &'static dyn CryptDE, config: NeighborhoodConfig) -> Self {
        if config.local_ip_addr == sentinel_ip_addr() && !config.neighbor_configs.is_empty() {
            panic! ("A SubstratumNode without an --ip setting is not decentralized and cannot have a --neighbors setting")
        }
        let gossip_acceptor: Box<dyn GossipAcceptor> = Box::new(GossipAcceptorReal::new(cryptde));
        let gossip_producer = Box::new(GossipProducerReal::new());
        let local_node_addr = NodeAddr::new(&config.local_ip_addr, &config.clandestine_port_list);
        let neighborhood_database = NeighborhoodDatabase::new(
            &cryptde.public_key(),
            &local_node_addr,
            config.earning_wallet.clone(),
            config.rate_pack.clone(),
            cryptde,
        );

        Neighborhood {
            cryptde,
            hopper: None,
            hopper_no_lookup: None,
            gossip_acceptor,
            gossip_producer,
            neighborhood_database,
            consuming_wallet_opt: config.consuming_wallet,
            next_return_route_id: 0,
            initial_neighbors: config.neighbor_configs,
            logger: Logger::new("Neighborhood"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Neighborhood>) -> NeighborhoodSubs {
        NeighborhoodSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            bootstrap: addr.clone().recipient::<BootstrapNeighborhoodNowMessage>(),
            node_query: addr.clone().recipient::<NodeQueryMessage>(),
            route_query: addr.clone().recipient::<RouteQueryMessage>(),
            update_node_record_metadata: addr.clone().recipient::<NodeRecordMetadataMessage>(),
            from_hopper: addr.clone().recipient::<ExpiredCoresPackage<Gossip>>(),
            dispatcher_node_query: addr.clone().recipient::<DispatcherNodeQueryMessage>(),
            remove_neighbor: addr.clone().recipient::<RemoveNeighborMessage>(),
            stream_shutdown_sub: addr.clone().recipient::<StreamShutdownMsg>(),
        }
    }

    fn log_incoming_gossip(&self, incoming_gossip: &Gossip, gossip_source: IpAddr) {
        let source = match self.neighborhood_database.node_by_ip(&gossip_source) {
            Some(node) => DotGossipEndpoint::from(node),
            None => DotGossipEndpoint::from(gossip_source),
        };
        trace!(
            self.logger,
            format!(
                "Received Gossip: {}",
                incoming_gossip.to_dot_graph(source, self.neighborhood_database.root())
            )
        );
    }

    fn handle_gossip(&mut self, incoming_gossip: Gossip, gossip_source: IpAddr) {
        info!(
            self.logger,
            format!(
                "Processing Gossip about {} Nodes",
                incoming_gossip.node_records.len()
            )
        );

        let record_count = incoming_gossip.node_records.len();
        let agrs: Vec<AccessibleGossipRecord> = incoming_gossip
            .node_records
            .into_iter()
            .flat_map(|gnr| AccessibleGossipRecord::try_from(gnr))
            .collect();

        if agrs.len() < record_count {
            // TODO: Instead of ignoring non-deserializable Gossip, ban the Node that sent it
            error!(
                self.logger,
                format!("Received non-deserializable Gossip from {}", gossip_source)
            );
            self.announce_gossip_handling_completion(record_count);
            return;
        }

        if agrs.iter().any(|agr| {
            !self.cryptde.verify_signature(
                &agr.signed_gossip,
                &agr.signature,
                &agr.inner.public_key,
            )
        }) {
            // TODO: Instead of ignoring badly-signed Gossip, ban the Node that sent it
            error!(
                self.logger,
                format!(
                    "Received Gossip with invalid signature from {}",
                    gossip_source
                )
            );
            self.announce_gossip_handling_completion(record_count);
            return;
        }

        self.handle_agrs(agrs, gossip_source);
        self.announce_gossip_handling_completion(record_count);
    }

    fn handle_agrs(&mut self, agrs: Vec<AccessibleGossipRecord>, gossip_source: IpAddr) {
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
                trace!(
                    self.logger,
                    format!("Gossip from {} ignored", gossip_source)
                );
                self.handle_gossip_ignored(ignored_node_name, gossip_record_count)
            }
            GossipAcceptanceResult::Ban(reason) => {
                warning!(self.logger, format!(
                    "Malefactor detected at {}, but malefactor bans not yet implemented; ignoring: {}",
                    gossip_source, reason
                ));
                self.handle_gossip_ignored(ignored_node_name, gossip_record_count);
            }
        }
    }

    fn announce_gossip_handling_completion(&self, record_count: usize) {
        info!(
            self.logger,
            format!("Finished processing Gossip about {} Nodes", record_count,)
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
                format!(
                    "Sending update Gossip about {} Nodes to Node {}",
                    gossip_len, neighbor
                )
            );
            self.hopper
                .as_ref()
                .expect("unbound hopper")
                .try_send(package)
                .expect("hopper is dead");
            trace!(
                self.logger,
                format!(
                    "Sent Gossip: {}",
                    gossip.to_dot_graph(
                        self.neighborhood_database.root(),
                        self.neighborhood_database
                            .node_by_key(*neighbor)
                            .expect("Node magically disappeared")
                    )
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
            false,
        )?;
        debug!(self.logger, format!("Route over: {:?}", over));
        let back = self.make_route_segment(
            over.keys.last().expect("Empty segment"),
            Some(&self.cryptde.public_key()),
            msg.minimum_hop_count,
            msg.return_component_opt.expect("No return component"),
            true,
        )?;
        debug!(self.logger, format!("Route back: {:?}", back));
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

        let has_long_segment = segments
            .iter()
            .find(|segment| segment.keys.len() > 2)
            .is_some();
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
        next_door_allowed: bool,
    ) -> Result<RouteSegment, String> {
        let mut node_seqs =
            self.complete_routes(vec![origin], target, minimum_hop_count, next_door_allowed);

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
                            .expect(format!("Unable to sort routes by desirable exit nodes: Missing NodeRecord for public key: [{}]", pk).as_str())
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

    fn validate_last_next_door_exit(
        previous_node: &NodeRecord,
        next_door_exit_allowed: bool,
    ) -> bool {
        next_door_exit_allowed || previous_node.node_addr_opt().is_none()
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
        target: Option<&'a PublicKey>,
        hops_remaining: usize,
        next_door_exit_allowed: bool,
    ) -> Vec<Vec<&'a PublicKey>> {
        let previous_node = self
            .neighborhood_database
            .node_by_key(prefix.last().expect("Empty prefix"))
            .expect("Node magically disappeared");
        // Check to see if we're done. If we are, all three of these qualifications will pass.
        if self.route_length_qualifies(hops_remaining)
            && self.last_key_qualifies(previous_node, target)
            && Self::validate_last_next_door_exit(previous_node, next_door_exit_allowed)
        {
            vec![prefix]
        } else if hops_remaining == 0
            && !Self::validate_last_next_door_exit(previous_node, next_door_exit_allowed)
        {
            //         don't return routes with next door exit nodes
            vec![]
        } else {
            // Go through all the neighbors and compute shorter routes through all the ones we're not already using.
            previous_node
                .full_neighbors(&self.neighborhood_database)
                .iter()
                .filter(|node_record| !prefix.contains(&node_record.public_key()))
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
                        target,
                        new_hops_remaining,
                        next_door_exit_allowed,
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
                error!(self.logger, e);
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
            format!(
                "Sent Gossip: {}",
                gossip.to_dot_graph(
                    self.neighborhood_database.root(),
                    (&target_key, &Some(target_node_addr))
                )
            )
        );
    }

    fn gossip_source_name(
        &self,
        accessible_gossip: &Vec<AccessibleGossipRecord>,
        gossip_source: IpAddr,
    ) -> String {
        match accessible_gossip.iter().find(|agr| {
            if let Some(ref node_addr) = agr.node_addr_opt {
                node_addr.ip_addr() == gossip_source
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
        let (neighbor_key, neighbor_node_addr) = match self
            .neighborhood_database
            .node_by_ip(&msg.peer_addr.ip())
        {
            None => {
                debug!(self.logger, format!("Received shutdown notification for stream to {}, but no neighbor found there - ignoring", msg.peer_addr));
                return;
            }
            Some(n) => (
                n.public_key().clone(),
                n.node_addr_opt().expect("NodeAddr suddenly disappeared"),
            ),
        };
        if !neighbor_node_addr.ports().contains(&msg.peer_addr.port()) {
            debug!(self.logger, format!("Received shutdown notification for stream to {}, but no neighbor found there - ignoring", msg.peer_addr));
            return;
        }
        match self.neighborhood_database.remove_neighbor(&neighbor_key) {
            Err(_) => panic!("Node suddenly disappeared"),
            Ok(true) => {
                debug!(
                    self.logger,
                    format!(
                        "Received shutdown notification for {} at {}",
                        neighbor_key, msg.peer_addr
                    )
                );
                self.gossip_to_neighbors()
            }
            Ok(false) => {
                debug!(self.logger, format! ("Received shutdown notification for {} at {}, but that Node is already isolated - ignoring", neighbor_key, msg.peer_addr));
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::super::gossip::GossipBuilder;
    use super::super::gossip::GossipNodeRecord;
    use super::super::neighborhood_test_utils::make_node_record;
    use super::*;
    use crate::neighborhood::gossip::Gossip;
    use crate::neighborhood::neighborhood_test_utils::{
        db_from_node, make_global_cryptde_node_record, neighborhood_from_nodes,
    };
    use crate::neighborhood::node_record::NodeRecordInner;
    use crate::persistent_configuration::TLS_PORT;
    use crate::stream_messages::{NonClandestineAttributes, RemovedStreamType};
    use crate::sub_lib::cryptde::{decodex, encodex, CryptData};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::dispatcher::Endpoint;
    use crate::sub_lib::hop::LiveHop;
    use crate::sub_lib::hopper::MessageType;
    use crate::sub_lib::neighborhood::sentinel_ip_addr;
    use crate::sub_lib::neighborhood::ExpectedServices;
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::test_utils::cryptde;
    use crate::test_utils::test_utils::make_meaningless_route;
    use crate::test_utils::test_utils::rate_pack;
    use crate::test_utils::test_utils::vec_to_set;
    use crate::test_utils::test_utils::{assert_contains, make_wallet};
    use actix::dev::{MessageResponse, ResponseChannel};
    use actix::Message;
    use actix::Recipient;
    use actix::System;
    use serde_cbor;
    use std::cell::RefCell;
    use std::convert::TryInto;
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tokio::prelude::Future;

    fn make_standard_subject() -> Neighborhood {
        let root_node = make_global_cryptde_node_record(9999, true);
        let neighbor_node = make_node_record(9998, true);
        neighborhood_from_nodes(&root_node, Some(&neighbor_node))
    }

    pub struct GossipAcceptorMock {
        handle_params: Arc<Mutex<Vec<(NeighborhoodDatabase, Vec<AccessibleGossipRecord>, IpAddr)>>>,
        handle_results: RefCell<Vec<GossipAcceptanceResult>>,
    }

    impl GossipAcceptor for GossipAcceptorMock {
        fn handle(
            &self,
            database: &mut NeighborhoodDatabase,
            agrs: Vec<AccessibleGossipRecord>,
            gossip_source: IpAddr,
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
                Mutex<Vec<(NeighborhoodDatabase, Vec<AccessibleGossipRecord>, IpAddr)>>,
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

    #[test]
    #[should_panic(
        expected = "A SubstratumNode without an --ip setting is not decentralized and cannot have a --neighbors setting"
    )]
    fn neighborhood_cannot_be_created_with_neighbors_and_default_ip() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_wallet("consuming"));
        let neighbor = make_node_record(1234, true);

        Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![NodeDescriptor {
                    public_key: neighbor.public_key().clone(),
                    node_addr: neighbor.node_addr_opt().unwrap().clone(),
                }
                .to_string(cryptde)],
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![0],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
        );
    }

    #[test]
    fn node_neighborhood_creates_single_node_database() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let this_node_addr = NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]);

        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                local_ip_addr: this_node_addr.ip_addr(),
                clandestine_port_list: this_node_addr.ports().clone(),
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: None,
                rate_pack: rate_pack(100),
            },
        );

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(root_node_record_ref.public_key(), cryptde.public_key());
        assert_eq!(root_node_record_ref.node_addr_opt(), Some(this_node_addr));
        assert_eq!(root_node_record_ref.half_neighbor_keys().len(), 0);
    }

    #[test]
    fn node_with_no_neighbor_configs_ignores_bootstrap_neighborhood_now_message() {
        init_test_logging();
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_wallet("consuming"));
        let system =
            System::new("node_with_no_neighbor_configs_ignores_bootstrap_neighborhood_now_message");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec![5678],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
        );
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<BootstrapNeighborhoodNowMessage> =
            addr.clone().recipient::<BootstrapNeighborhoodNowMessage>();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        addr.try_send(BindMessage { peer_actors }).unwrap();

        sub.try_send(BootstrapNeighborhoodNowMessage {}).unwrap();

        System::current().stop_with_code(0);
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
        TestLogHandler::new()
            .exists_log_containing("INFO: Neighborhood: No Nodes to report to; continuing");
    }

    #[test]
    #[should_panic(
        expected = "--neighbors must be <public key>:<ip address>:<port>;<port>..., not 'ooga'"
    )]
    fn node_with_bad_neighbor_config_panics() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_wallet("consuming"));
        let system =
            System::new("node_with_no_neighbor_configs_ignores_bootstrap_neighborhood_now_message");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![String::from("ooga"), String::from("booga")],
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec![5678],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
        );
        let addr: Addr<Neighborhood> = subject.start();
        let sub: Recipient<BootstrapNeighborhoodNowMessage> =
            addr.clone().recipient::<BootstrapNeighborhoodNowMessage>();
        let peer_actors = peer_actors_builder().build();
        addr.try_send(BindMessage { peer_actors }).unwrap();

        sub.try_send(BootstrapNeighborhoodNowMessage {}).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[test]
    fn neighborhood_adds_nodes_and_links() {
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_wallet("consuming"));
        let one_neighbor_node = make_node_record(3456, true);
        let another_neighbor_node = make_node_record(4567, true);
        let this_node_addr = NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]);

        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![
                    NodeDescriptor {
                        public_key: one_neighbor_node.public_key().clone(),
                        node_addr: one_neighbor_node.node_addr_opt().unwrap().clone(),
                    }
                    .to_string(cryptde),
                    NodeDescriptor {
                        public_key: another_neighbor_node.public_key().clone(),
                        node_addr: another_neighbor_node.node_addr_opt().unwrap().clone(),
                    }
                    .to_string(cryptde),
                ],
                local_ip_addr: this_node_addr.ip_addr(),
                clandestine_port_list: this_node_addr.ports().clone(),
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
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
                NodeDescriptor {
                    public_key: one_neighbor_node.public_key().clone(),
                    node_addr: one_neighbor_node.node_addr_opt().unwrap()
                }
                .to_string(cryptde),
                NodeDescriptor {
                    public_key: another_neighbor_node.public_key().clone(),
                    node_addr: another_neighbor_node.node_addr_opt().unwrap()
                }
                .to_string(cryptde)
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
        let consuming_wallet = Some(make_wallet("consuming"));
        let system =
            System::new("node_query_responds_with_none_when_key_query_matches_no_configured_data");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![NodeDescriptor {
                    public_key: PublicKey::new(&b"booga"[..]),
                    node_addr: NodeAddr::new(
                        &IpAddr::from_str("1.2.3.4").unwrap(),
                        &vec![1234, 2345],
                    ),
                }
                .to_string(cryptde)],
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec![5678],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
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
        let consuming_wallet = Some(make_wallet("consuming"));
        let system =
            System::new("node_query_responds_with_result_when_key_query_matches_configured_data");
        let one_neighbor = make_node_record(2345, true);
        let another_neighbor = make_node_record(3456, true);
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![node_record_to_neighbor_config(&one_neighbor, cryptde)],
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec![5678],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
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
        let consuming_wallet = Some(make_wallet("consuming"));
        let system = System::new(
            "node_query_responds_with_none_when_ip_address_query_matches_no_configured_data",
        );
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![NodeDescriptor {
                    public_key: PublicKey::new(&b"booga"[..]),
                    node_addr: NodeAddr::new(
                        &IpAddr::from_str("1.2.3.4").unwrap(),
                        &vec![1234, 2345],
                    ),
                }
                .to_string(cryptde)],
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec![5678],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
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
            NeighborhoodConfig {
                neighbor_configs: vec![NodeDescriptor {
                    public_key: node_record.public_key().clone(),
                    node_addr: node_record.node_addr_opt().unwrap().clone(),
                }
                .to_string(cryptde)],
                local_ip_addr: node_record.node_addr_opt().as_ref().unwrap().ip_addr(),
                clandestine_port_list: node_record
                    .node_addr_opt()
                    .as_ref()
                    .unwrap()
                    .ports()
                    .clone(),
                earning_wallet: node_record.earning_wallet(),
                consuming_wallet: None,
                rate_pack: rate_pack(100),
            },
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
        let segment = |nodes: Vec<&NodeRecord>, component: Component| {
            RouteSegment::new(
                nodes.into_iter().map(|n| n.public_key()).collect(),
                component,
            )
        };

        let result = data_route.wait().unwrap().unwrap();
        let expected_response = RouteQueryResponse {
            route: Route::round_trip(
                segment(vec![p, q, r], Component::ProxyClient),
                segment(vec![r, q, p], Component::ProxyServer),
                cryptde,
                consuming_wallet_opt,
                0,
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

            Q---P---R
                |   |
            T---S---+

            Test is written from the standpoint of P
    */

    #[test]
    fn complete_routes_exercise() {
        let mut subject = make_standard_subject();
        let db = &mut subject.neighborhood_database;
        let p = &db.root_mut().public_key().clone(); // 9e7p7un06eHs6frl5A
        let q = &db.add_node(make_node_record(3456, true)).unwrap(); // AwQFBg
        let r = &db.add_node(make_node_record(4567, true)).unwrap(); // BAUGBw
        let s = &db.add_node(make_node_record(5678, true)).unwrap(); // BQYHCA
        let t = &db.add_node(make_node_record(6789, true)).unwrap(); // BgcICQ
        db.add_arbitrary_full_neighbor(q, p);
        db.add_arbitrary_full_neighbor(p, r);
        db.add_arbitrary_full_neighbor(p, s);
        db.add_arbitrary_full_neighbor(t, s);
        db.add_arbitrary_full_neighbor(s, r);

        let contains = |routes: &Vec<Vec<&PublicKey>>, expected_keys: Vec<&PublicKey>| {
            assert_contains(&routes, &expected_keys);
        };

        // At least two hops from P to anywhere standard
        let routes = subject.complete_routes(vec![p], None, 2, true);

        contains(&routes, vec![p, s, t]);
        contains(&routes, vec![p, r, s]);
        contains(&routes, vec![p, s, r]);
        assert_eq!(3, routes.len());

        // At least two hops from P to T
        let routes = subject.complete_routes(vec![p], Some(t), 2, true);

        contains(&routes, vec![p, s, t]);
        contains(&routes, vec![p, r, s, t]);
        assert_eq!(2, routes.len());

        // At least two hops from P to S - one choice
        let routes = subject.complete_routes(vec![p], Some(s), 2, true);

        contains(&routes, vec![p, r, s]);
        assert_eq!(1, routes.len());

        // At least two hops from P to Q - impossible
        let routes = subject.complete_routes(vec![p], Some(q), 2, true);

        assert_eq!(0, routes.len());
    }

    #[test]
    fn gossips_after_removing_a_neighbor() {
        let (hopper, hopper_awaiter, hopper_recording) = make_recorder();
        let cryptde = cryptde();
        let earning_wallet = make_wallet("earning");
        let consuming_wallet = Some(make_wallet("consuming"));
        let this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            100,
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
                NeighborhoodConfig {
                    neighbor_configs: vec![],
                    local_ip_addr: this_node_inside.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: this_node_inside.node_addr_opt().unwrap().ports(),
                    earning_wallet: earning_wallet.clone(),
                    consuming_wallet: consuming_wallet.clone(),
                    rate_pack: rate_pack(100),
                },
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

        let other_neighbor_cryptde = CryptDENull::from(other_neighbor.public_key());
        hopper_awaiter.await_message_count(1);
        let locked_recording = hopper_recording.lock().unwrap();
        let package: &IncipientCoresPackage = locked_recording.get_record(0);
        let gossip = match decodex(&other_neighbor_cryptde, &package.payload).unwrap() {
            MessageType::Gossip(g) => g,
            x => panic!("Expected MessageType::Gossip, got {:?}", x),
        };
        type Digest = (PublicKey, Vec<u8>, bool, u32, Vec<PublicKey>);
        let to_digest = |gnr: GossipNodeRecord| {
            let node_addr_opt = gnr.node_addr_opt.clone();
            let inner = NodeRecordInner::try_from(gnr).unwrap();
            let mut neighbors_vec = inner.neighbors.into_iter().collect::<Vec<PublicKey>>();
            neighbors_vec.sort_unstable_by(|a, b| a.cmp(&b));
            (
                inner.public_key.clone(),
                inner.public_key.into(),
                node_addr_opt.is_some(),
                inner.version,
                neighbors_vec,
            )
        };
        let mut digests = gossip
            .node_records
            .into_iter()
            .map(|gnr| to_digest(gnr))
            .collect::<Vec<Digest>>();
        digests.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            vec![
                (
                    removed_neighbor.public_key().clone(),
                    removed_neighbor.public_key().clone().into(),
                    false,
                    0,
                    vec![
                        other_neighbor.public_key().clone(),
                        this_node.public_key().clone()
                    ]
                ),
                (
                    this_node.public_key().clone(),
                    this_node.public_key().clone().into(),
                    true,
                    1,
                    vec![other_neighbor.public_key().clone()]
                )
            ],
            digests
        );
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
            immediate_neighbor_ip: subject_node.node_addr_opt().unwrap().ip_addr(),
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
        assert_eq!(
            subject_node.node_addr_opt().unwrap().ip_addr(),
            call_gossip_source
        );
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

        subject.handle_gossip(Gossip::new(vec![]), IpAddr::from_str("1.1.1.1").unwrap());

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<NoLookupIncipientCoresPackage>(0);
        assert_eq!(1, hopper_recording.len());
        assert_eq!(introduction_target_node.public_key(), &package.public_key);
        let gossip = match decodex::<MessageType>(
            &CryptDENull::from(introduction_target_node.public_key()),
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

        subject.handle_gossip(Gossip::new(vec![]), IpAddr::from_str("1.1.1.1").unwrap());

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
                        &MessageType::Gossip(gossip.clone())
                    )
                    .unwrap()
                ),
                (
                    half_neighbor.public_key().clone(),
                    encodex(
                        cryptde(),
                        half_neighbor.public_key(),
                        &MessageType::Gossip(gossip.clone())
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
        let gossip_source = IpAddr::from_str("8.6.5.4").unwrap();

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
                &CryptDENull::from(debut_node.public_key()),
                &package.payload
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
            subject_node.node_addr_opt().unwrap().ip_addr(),
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
            subject_node.node_addr_opt().unwrap().ip_addr(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(0, hopper_recording.len());
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("WARN: Neighborhood: Malefactor detected at 5.5.5.5, but malefactor bans not yet implemented; ignoring: Bad guy");
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
        let gossip_source = IpAddr::from_str("1.2.3.4").unwrap();

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
        let gossip_source = IpAddr::from_str("1.2.3.4").unwrap();

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
            immediate_neighbor_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            paying_wallet: Some(make_wallet("consuming")),
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
                NeighborhoodConfig {
                    neighbor_configs: vec![],
                    local_ip_addr: this_node_inside.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: this_node_inside.node_addr_opt().unwrap().ports(),
                    earning_wallet: this_node_inside.earning_wallet(),
                    consuming_wallet: None,
                    rate_pack: rate_pack(100),
                },
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
            &format!("\"BAYFBw\" [label=\"v0\\nBAYFBw\\n4.6.5.7:4657\"];"),
            5000,
        );

        tlh.exists_log_containing("Received Gossip: digraph db { ");
        tlh.exists_log_containing("\"AQMCBA\" [label=\"v0\\nAQMCBA\"];");
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
            NeighborhoodConfig {
                neighbor_configs: vec![NodeDescriptor {
                    public_key: neighbor_inside.public_key().clone(),
                    node_addr: neighbor_inside.node_addr_opt().unwrap().clone(),
                }
                .to_string(cryptde)],
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec![1234],
                earning_wallet: NodeRecord::earning_wallet_from_key(&cryptde.public_key()),
                consuming_wallet: NodeRecord::consuming_wallet_from_key(&cryptde.public_key()),
                rate_pack: rate_pack(100),
            },
        );
        let this_node = subject.neighborhood_database.root().clone();
        thread::spawn(move || {
            let system = System::new("node_gossips_to_neighbors_on_startup");
            let addr: Addr<Neighborhood> = subject.start();
            let peer_actors = peer_actors_builder().hopper(hopper).build();
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub: Recipient<BootstrapNeighborhoodNowMessage> =
                addr.recipient::<BootstrapNeighborhoodNowMessage>();

            sub.try_send(BootstrapNeighborhoodNowMessage {}).unwrap();

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let locked_recording = hopper_recording.lock().unwrap();
        let package_ref: &NoLookupIncipientCoresPackage = locked_recording.get_record(0);
        let neighbor_node_cryptde = CryptDENull::from(neighbor.public_key());
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

    fn node_record_to_neighbor_config(node_record_ref: &NodeRecord, cryptde: &CryptDE) -> String {
        NodeDescriptor {
            public_key: node_record_ref.public_key().clone(),
            node_addr: node_record_ref.node_addr_opt().unwrap().clone(),
        }
        .to_string(cryptde)
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
        let consuming_wallet = Some(make_wallet("consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new ("neighborhood_sends_node_query_response_with_none_when_key_query_matches_no_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();

            let subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![NodeDescriptor {
                        public_key: PublicKey::new(&b"booga"[..]),
                        node_addr: NodeAddr::new(
                            &IpAddr::from_str("1.2.3.4").unwrap(),
                            &vec![1234, 2345],
                        ),
                    }
                    .to_string(cryptde)],
                    local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                    clandestine_port_list: vec![5678],
                    earning_wallet: earning_wallet.clone(),
                    consuming_wallet: consuming_wallet.clone(),
                    rate_pack: rate_pack(100),
                },
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
        let consuming_wallet = Some(make_wallet("consuming"));
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
                NeighborhoodConfig {
                    neighbor_configs: vec![node_record_to_neighbor_config(&one_neighbor, cryptde)],
                    local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                    clandestine_port_list: vec![5678],
                    earning_wallet: earning_wallet.clone(),
                    consuming_wallet: consuming_wallet.clone(),
                    rate_pack: rate_pack(100),
                },
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
        let consuming_wallet = Some(make_wallet("consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("neighborhood_sends_node_query_response_with_none_when_ip_address_query_matches_no_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();
            let subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![NodeDescriptor {
                        public_key: PublicKey::new(&b"booga"[..]),
                        node_addr: NodeAddr::new(
                            &IpAddr::from_str("1.2.3.4").unwrap(),
                            &vec![1234, 2345],
                        ),
                    }
                    .to_string(cryptde)],
                    local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                    clandestine_port_list: vec![5678],
                    earning_wallet: earning_wallet.clone(),
                    consuming_wallet: consuming_wallet.clone(),
                    rate_pack: rate_pack(100),
                },
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
            let mut subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![NodeDescriptor {
                        public_key: node_record.public_key().clone(),
                        node_addr: node_record.node_addr_opt().unwrap().clone(),
                    }
                    .to_string(cryptde)],
                    local_ip_addr: node_record.node_addr_opt().as_ref().unwrap().ip_addr(),
                    clandestine_port_list: node_record
                        .node_addr_opt()
                        .as_ref()
                        .unwrap()
                        .ports()
                        .clone(),
                    earning_wallet: node_record.earning_wallet(),
                    consuming_wallet: None,
                    rate_pack: rate_pack(100),
                },
            );
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
    fn make_round_trip_route_returns_error_when_no_non_next_door_neighbor_found() {
        let next_door_neighbor = make_node_record(3, true);
        let subject_node = make_global_cryptde_node_record(5555, true); // 9e7p7un06eHs6frl5A
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&next_door_neighbor));

        subject
            .neighborhood_database
            .add_node(next_door_neighbor.clone())
            .unwrap();

        subject.neighborhood_database.add_arbitrary_full_neighbor(
            subject_node.public_key(),
            next_door_neighbor.public_key(),
        );

        let minimum_hop_count = 1;

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

        let next_door_neighbor_cryptde = CryptDENull::from(&next_door_neighbor.public_key());
        let exit_node_cryptde = CryptDENull::from(&exit_node.public_key());

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
        TestLogHandler::new ().exists_log_containing (&format!("DEBUG: Neighborhood: Received shutdown notification for stream to {}, but no neighbor found there - ignoring", unrecognized_socket_addr));
    }

    #[test]
    fn handle_stream_shutdown_handles_socket_addr_with_unknown_port() {
        init_test_logging();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let system = System::new("test");
        let neighbor_node = make_node_record(3123, true);
        let neighbor_node_addr = neighbor_node.node_addr_opt().unwrap();
        let neighbor_node_socket_addr =
            SocketAddr::new(neighbor_node_addr.ip_addr(), neighbor_node_addr.ports()[0]);
        let unrecognized_socket_addr = SocketAddr::new(
            neighbor_node_socket_addr.ip(),
            neighbor_node_socket_addr.port() + 1,
        );
        let subject_node = make_global_cryptde_node_record(1345, true);
        let mut subject = neighborhood_from_nodes(&subject_node, None);
        subject
            .neighborhood_database
            .add_node(neighbor_node.clone())
            .unwrap();
        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(subject_node.public_key(), neighbor_node.public_key());
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        subject.hopper = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_stream_shutdown_msg(StreamShutdownMsg {
            peer_addr: SocketAddr::new(
                neighbor_node_socket_addr.ip(),
                neighbor_node_socket_addr.port() + 1,
            ),
            stream_type: RemovedStreamType::Clandestine,
            report_to_counterpart: false,
        });

        System::current().stop_with_code(0);
        system.run();

        assert_eq!(subject.neighborhood_database.keys().len(), 2);
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
        TestLogHandler::new ().exists_log_containing (&format!("DEBUG: Neighborhood: Received shutdown notification for stream to {}, but no neighbor found there - ignoring", unrecognized_socket_addr));
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
                inactive_neighbor_node.public_key()
            ),
            false
        );
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 0);
        TestLogHandler::new ().exists_log_containing (&format!("DEBUG: Neighborhood: Received shutdown notification for {} at {}, but that Node is already isolated - ignoring", inactive_neighbor_node.public_key(), inactive_neighbor_node_socket_addr));
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
                shutdown_neighbor_node.public_key()
            ),
            false
        );
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(hopper_recording.len(), 1);
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: Neighborhood: Received shutdown notification for {} at {}",
            shutdown_neighbor_node.public_key(),
            shutdown_neighbor_node_socket_addr
        ));
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
