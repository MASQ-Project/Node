// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::gossip_acceptor::GossipAcceptor;
use super::gossip_acceptor::GossipAcceptorReal;
use super::gossip_producer::GossipProducer;
use super::gossip_producer::GossipProducerReal;
use super::neighborhood_database::NeighborhoodDatabase;
use super::node_record::NodeRecord;
use crate::neighborhood::gossip::Gossip;
use crate::neighborhood::gossip_acceptor::GossipAcceptanceResult;
use crate::sub_lib::accountant;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::dispatcher::Component;
use crate::sub_lib::hopper::{ExpiredCoresPackage, NoLookupIncipientCoresPackage};
use crate::sub_lib::hopper::{IncipientCoresPackage, MessageType};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::neighborhood::BootstrapNeighborhoodNowMessage;
use crate::sub_lib::neighborhood::DispatcherNodeQueryMessage;
use crate::sub_lib::neighborhood::ExpectedService;
use crate::sub_lib::neighborhood::ExpectedServices;
use crate::sub_lib::neighborhood::NeighborhoodConfig;
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::neighborhood::NodeDescriptor;
use crate::sub_lib::neighborhood::NodeQueryMessage;
use crate::sub_lib::neighborhood::RemoveNeighborMessage;
use crate::sub_lib::neighborhood::RouteQueryMessage;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::neighborhood::TargetType;
use crate::sub_lib::neighborhood::ZERO_RATE_PACK;
use crate::sub_lib::neighborhood::{sentinel_ip_addr, NodeRecordMetadataMessage};
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::route::Route;
use crate::sub_lib::route::RouteSegment;
use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use crate::sub_lib::utils::plus;
use crate::sub_lib::utils::NODE_MAILBOX_CAPACITY;
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MessageResult;
use actix::Recipient;
use std::cmp::Ordering;
use std::net::IpAddr;

pub struct Neighborhood {
    cryptde: &'static dyn CryptDE,
    hopper: Option<Recipient<IncipientCoresPackage>>,
    hopper_no_lookup: Option<Recipient<NoLookupIncipientCoresPackage>>,
    gossip_acceptor: Box<dyn GossipAcceptor>,
    gossip_producer: Box<dyn GossipProducer>,
    neighborhood_database: NeighborhoodDatabase,
    next_return_route_id: u32,
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
        let (bootstrap_node_keys, keys_to_report) = self
            .neighborhood_database
            .keys()
            .into_iter()
            .fold((vec![], vec![]), |so_far, key| {
                let (bootstrap_node_keys, keys_to_report) = so_far;
                let node = self
                    .neighborhood_database
                    .node_by_key(key)
                    .expect("Node magically disappeared");
                if node.is_bootstrap_node()
                    && (node.public_key() != self.neighborhood_database.root().public_key())
                {
                    (plus(bootstrap_node_keys, key), keys_to_report)
                } else {
                    (bootstrap_node_keys, plus(keys_to_report, key))
                }
            });

        if bootstrap_node_keys.is_empty() {
            self.logger
                .info(format!("No bootstrap Nodes to report to; continuing"));
            return ();
        }
        if keys_to_report.is_empty() {
            self.logger
                .info(format!("Nothing to report to bootstrap Node(s)"));
            return ();
        }
        bootstrap_node_keys
            .into_iter()
            .for_each(|bootstrap_node_key| {
                let gossip = self
                    .gossip_producer
                    .produce(&self.neighborhood_database, &bootstrap_node_key);
                let route = self.create_single_hop_route(&bootstrap_node_key);
                let package = IncipientCoresPackage::new(
                    self.cryptde,
                    route,
                    gossip.clone().into(),
                    &bootstrap_node_key,
                )
                .expect("Key magically disappeared");

                self.logger.info(format!(
                    "Sending initial Gossip about {} nodes to bootstrap Node at {}:{}",
                    gossip.node_records.len(),
                    bootstrap_node_key,
                    self.neighborhood_database
                        .node_by_key(&bootstrap_node_key)
                        .expect("Node magically disappeared")
                        .node_addr_opt()
                        .as_ref()
                        .expect("internal error: must know NodeAddr of bootstrap Node")
                ));
                self.hopper
                    .as_ref()
                    .expect("unbound hopper")
                    .try_send(package)
                    .expect("hopper is dead");
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
            Some(node_record_ref) => Some(NodeDescriptor::new(
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
            Some(node_record_ref) => Some(NodeDescriptor::new(
                node_record_ref.public_key().clone(),
                match node_record_ref.node_addr_opt() {
                    Some(node_addr_ref) => Some(node_addr_ref.clone()),
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
                self.logger
                    .debug(format!("Processed {} into {:?}", msg_str, response.clone()));
                Some(response)
            }
            Err(msg) => {
                self.logger
                    .error(format!("Unsatisfied route query: {}", msg));
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
        self.handle_gossip(&incoming_gossip, msg.immediate_neighbor_ip);
    }
}

impl Handler<RemoveNeighborMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: RemoveNeighborMessage, _ctx: &mut Self::Context) -> Self::Result {
        let public_key = &msg.public_key;
        match self.neighborhood_database.remove_neighbor(public_key) {
            Err(s) => self.logger.error(s),
            Ok(db_changed) => {
                if db_changed {
                    self.gossip_to_neighbors();
                    self.logger
                        .info(format!("removed neighbor by public key: {}", public_key))
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

impl Neighborhood {
    pub fn new(cryptde: &'static dyn CryptDE, config: NeighborhoodConfig) -> Self {
        if config.local_ip_addr == sentinel_ip_addr() {
            if !config.neighbor_configs.is_empty() {
                panic! ("A SubstratumNode without an --ip setting is not decentralized and cannot have any --neighbor settings")
            }
            if !config.clandestine_port_list.is_empty() {
                panic! ("A SubstratumNode without an --ip setting is not decentralized and cannot have any --port_count setting other than 0")
            }
            if config.is_bootstrap_node {
                panic! ("A SubstratumNode without an --ip setting is not decentralized and cannot be --node_type bootstrap")
            }
        } else if (config.neighbor_configs.is_empty() && !config.is_bootstrap_node)
            || config.clandestine_port_list.is_empty()
        {
            panic! ("An --ip setting indicates that you want to decentralize, but you also need at least one --neighbor setting or --node_type bootstrap for that, and a --port_count greater than 0")
        }
        let gossip_acceptor: Box<dyn GossipAcceptor> = Box::new(GossipAcceptorReal::new());
        let gossip_producer = Box::new(GossipProducerReal::new());
        let local_node_addr = NodeAddr::new(&config.local_ip_addr, &config.clandestine_port_list);
        let mut neighborhood_database = NeighborhoodDatabase::new(
            &cryptde.public_key(),
            &local_node_addr,
            config.earning_wallet.clone(),
            config.consuming_wallet.clone(),
            config.rate_pack.clone(),
            config.is_bootstrap_node,
            cryptde,
        );

        let add_node = |neighborhood_database: &mut NeighborhoodDatabase,
                        neighbor: &(PublicKey, NodeAddr),
                        is_bootstrap_node: bool| {
            let (key, node_addr) = neighbor;
            neighborhood_database
                .add_node(&NodeRecord::new(
                    &key,
                    Some(&node_addr),
                    accountant::DEFAULT_EARNING_WALLET.clone(),
                    None,
                    // TODO: This is wrong: see TODO about local-Node-only below to correct it.
                    ZERO_RATE_PACK.clone(),
                    is_bootstrap_node,
                    None,
                    0,
                ))
                .expect(&format!("Database already contains node {:?}", key));
            neighborhood_database
                .add_half_neighbor(&key)
                .expect("internal error");
        };

        // TODO: Only the local Node should be added to the database here in the constructor.
        // Local descriptors aren't enough information to add about other Nodes. We should keep
        // the local descriptors from --neighbor and use them only to direct our initial Gossip
        // messages when the BootstrapNeighborhoodNowMessage arrives. The Gossip that arrives
        // later from those Nodes will automatically populate the NeighborhoodDatabase with
        // everything it needs.
        config
            .neighbor_configs
            .iter()
            .for_each(|neighbor| add_node(&mut neighborhood_database, neighbor, true));

        Neighborhood {
            cryptde,
            hopper: None,
            hopper_no_lookup: None,
            gossip_acceptor,
            gossip_producer,
            neighborhood_database,
            next_return_route_id: 0,
            logger: Logger::new("Neighborhood"),
        }
    }

    fn log_incoming_gossip(&self, incoming_gossip: &Gossip, gossip_source: IpAddr) {
        let source = match self.neighborhood_database.node_by_ip(&gossip_source) {
            Some(node) => node.clone(),
            None => Self::ip_only_node_record(gossip_source),
        };
        self.logger.trace(format!(
            "Received Gossip: {}",
            incoming_gossip.to_dot_graph(&source, self.neighborhood_database.root())
        ));
    }

    fn handle_gossip(&mut self, incoming_gossip: &Gossip, gossip_source: IpAddr) {
        self.logger.info(format!(
            "Processing Gossip about {} Nodes",
            incoming_gossip.node_records.len()
        ));

        let acceptance_result = self.gossip_acceptor.handle(
            &mut self.neighborhood_database,
            &incoming_gossip,
            gossip_source,
        );
        match acceptance_result {
            GossipAcceptanceResult::Accepted(debut_triples) => {
                self.handle_gossip_acceptance(debut_triples)
            }
            GossipAcceptanceResult::Relay(relay_gossip, relay_target, relay_node_addr) => {
                self.handle_gossip_relay(relay_gossip, relay_target, relay_node_addr, gossip_source)
            }
            GossipAcceptanceResult::Ignored => {
                self.handle_gossip_ignored(&incoming_gossip, gossip_source)
            }
        }
        self.logger.info(format!(
            "Finished processing Gossip about {} Nodes",
            incoming_gossip.node_records.len(),
        ));
        self.logger.debug(format!(
            "Current database: {}",
            self.neighborhood_database.to_dot_graph()
        ));
    }

    fn gossip_to_neighbors(&self) {
        self.gossip_to(
            self.neighborhood_database
                .root()
                .half_neighbor_keys()
                .into_iter()
                .collect(),
        );
    }

    fn gossip_to(&self, neighbors: Vec<&PublicKey>) {
        neighbors.iter().for_each(|neighbor| {
            let gossip = self
                .gossip_producer
                .produce(&self.neighborhood_database, neighbor);
            let gossip_len = gossip.node_records.len();
            let route = self.create_single_hop_route(neighbor);
            let package = IncipientCoresPackage::new(self.cryptde, route, gossip.into(), neighbor)
                .expect("Key magically disappeared");
            self.logger.info(format!(
                "Sending update Gossip about {} Nodes to Node {}",
                gossip_len, neighbor
            ));
            self.hopper
                .as_ref()
                .expect("unbound hopper")
                .try_send(package)
                .expect("hopper is dead");
        });
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
        }
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
        let local_target_type = if self.neighborhood_database.root().is_bootstrap_node() {
            TargetType::Bootstrap
        } else {
            TargetType::Standard
        };
        let over = self.make_route_segment(
            &self.cryptde.public_key(),
            msg.target_key_opt.as_ref(),
            msg.target_type,
            msg.minimum_hop_count,
            msg.target_component,
        )?;
        self.logger.debug(format!("Route over: {:?}", over));
        let back = self.make_route_segment(
            over.keys.last().expect("Empty segment"),
            Some(&self.cryptde.public_key()),
            local_target_type,
            msg.minimum_hop_count,
            msg.return_component_opt.expect("No return component"),
        )?;
        self.logger.debug(format!("Route back: {:?}", back));
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

        let consuming_wallet_opt = self.neighborhood_database.root().consuming_wallet();
        let has_long_segment = segments
            .iter()
            .find(|segment| segment.keys.len() > 2)
            .is_some();
        if consuming_wallet_opt.is_none() && has_long_segment {
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
                consuming_wallet_opt,
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
        target_type: TargetType,
        minimum_hop_count: usize,
        target_component: Component,
    ) -> Result<RouteSegment, String> {
        let mut node_seqs =
            self.complete_routes(vec![origin], target, target_type, minimum_hop_count);

        if node_seqs.is_empty() {
            let target_str = match target {
                Some(t) => format!(" {}", t),
                None => String::new(),
            };
            Err(format!(
                "Couldn't find any routes: at least {}-hop from {} to {:?} at {:?}{}",
                minimum_hop_count, origin, target_component, target_type, target_str
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

    fn last_type_qualifies(&self, last_node_ref: &NodeRecord, target_type: TargetType) -> bool {
        (target_type == TargetType::Bootstrap) == last_node_ref.is_bootstrap_node()
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
        target_type: TargetType, // TODO: Remove this parameter: it will only ever work with the value TargetType::Standard.
        hops_remaining: usize,
    ) -> Vec<Vec<&'a PublicKey>> {
        let last_node_ref = self
            .neighborhood_database
            .node_by_key(prefix.last().expect("Empty prefix"))
            .expect("Node magically disappeared");
        // Check to see if we're done. If we are, all three of these qualifications will pass.
        if self.route_length_qualifies(hops_remaining)
            && self.last_key_qualifies(last_node_ref, target)
            && self.last_type_qualifies(last_node_ref, target_type)
        {
            vec![prefix]
        }
        // If we're not done, then last_node is for routing, and bootstrap Nodes don't route.
        else if last_node_ref.is_bootstrap_node() {
            vec![]
        }
        // Go through all the neighbors and compute shorter routes through all the ones we're not already using.
        else {
            last_node_ref
                .full_neighbors(&self.neighborhood_database)
                .iter()
                .filter(|node_record_ref_ref_ref| {
                    !prefix.contains(&node_record_ref_ref_ref.public_key())
                })
                .flat_map(|node_record_ref_ref| {
                    let mut new_prefix = prefix.clone();
                    new_prefix.push(node_record_ref_ref.public_key());
                    let new_hops_remaining = if hops_remaining == 0 {
                        0
                    } else {
                        hops_remaining - 1
                    };
                    self.complete_routes(
                        new_prefix.clone(),
                        target,
                        target_type,
                        new_hops_remaining,
                    )
                })
                .collect()
        }
    }

    fn ip_only_node_record(ip_addr: IpAddr) -> NodeRecord {
        NodeRecord::new(
            &PublicKey::new(&[]),
            Some(&NodeAddr::new(&ip_addr, &vec![])),
            Wallet::new(""),
            None,
            ZERO_RATE_PACK,
            false,
            None,
            0,
        )
    }

    fn handle_gossip_acceptance(&self, debut_triples: Vec<(Gossip, PublicKey, NodeAddr)>) {
        if debut_triples.is_empty() {
            self.send_gossip_updates()
        } else {
            self.send_debuts(debut_triples)
        }
    }

    fn handle_gossip_relay(
        &self,
        relay_gossip: Gossip,
        relay_target: PublicKey,
        relay_node_addr: NodeAddr,
        gossip_source: IpAddr,
    ) {
        let relayed_node = self.gossip_source_name(&relay_gossip, gossip_source);
        self.logger.info(format!(
            "Relaying debut from Node {} to neighbor {}",
            relayed_node, relay_target
        ));
        self.send_gossip(relay_gossip, relay_target, relay_node_addr);
    }

    fn handle_gossip_ignored(&self, ignored_gossip: &Gossip, gossip_source: IpAddr) {
        let ignored_node = self.gossip_source_name(&ignored_gossip, gossip_source);
        self.logger.info(format!(
            "Ignored Gossip about {} Nodes from {}",
            ignored_gossip.node_records.len(),
            ignored_node
        ));
    }

    fn send_gossip_updates(&self) {
        self.gossip_to_neighbors()
    }

    fn send_debuts(&self, debut_triples: Vec<(Gossip, PublicKey, NodeAddr)>) {
        for (debut, debut_target, debut_node_addr) in debut_triples {
            self.logger.info(format!(
                "Accepting introduction to Node {}/{}: sending debut",
                debut_target, debut_node_addr
            ));
            self.send_gossip(debut, debut_target, debut_node_addr);
        }
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
                self.logger.error(e);
                return ();
            }
        };
        self.hopper_no_lookup
            .as_ref()
            .expect("No-lookup Hopper is unbound")
            .try_send(package)
            .expect("Hopper is dead");
        self.logger.debug(format!(
            "Sent Gossip: {}",
            gossip.to_dot_graph(
                self.neighborhood_database.root(),
                (&self.neighborhood_database, &target_key)
            )
        ));
    }

    fn gossip_source_name(&self, gossip: &Gossip, gossip_source: IpAddr) -> String {
        match gossip.node_records.iter().find(|gnr| {
            if let Some(ref node_addr) = gnr.inner.node_addr_opt {
                node_addr.ip_addr() == gossip_source
            } else {
                false
            }
        }) {
            Some(gnr) => format!("{}", gnr.public_key()),
            None => format!("{}", gossip_source),
        }
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
        db_from_node, make_cryptde_node_record, neighborhood_from_nodes,
    };
    use crate::neighborhood::node_record::NodeRecordInner;
    use crate::sub_lib::cryptde::decodex;
    use crate::sub_lib::cryptde::encodex;
    use crate::sub_lib::cryptde::CryptData;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::dispatcher::Endpoint;
    use crate::sub_lib::hopper::MessageType;
    use crate::sub_lib::neighborhood::sentinel_ip_addr;
    use crate::sub_lib::neighborhood::ExpectedServices;
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::test_utils::assert_contains;
    use crate::test_utils::test_utils::cryptde;
    use crate::test_utils::test_utils::make_meaningless_route;
    use crate::test_utils::test_utils::rate_pack;
    use crate::test_utils::test_utils::vec_to_set;
    use actix::dev::{MessageResponse, ResponseChannel};
    use actix::Message;
    use actix::Recipient;
    use actix::System;
    use serde_cbor;
    use std::cell::RefCell;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use tokio::prelude::Future;

    fn make_standard_subject() -> Neighborhood {
        let root_node = make_cryptde_node_record(9999, true, false);
        let bootstrap_node = make_node_record(9998, true, true);
        neighborhood_from_nodes(&root_node, Some(&bootstrap_node))
    }

    pub struct GossipAcceptorMock {
        handle_params: Arc<Mutex<Vec<(NeighborhoodDatabase, Gossip, IpAddr)>>>,
        handle_results: RefCell<Vec<GossipAcceptanceResult>>,
    }

    impl GossipAcceptor for GossipAcceptorMock {
        fn handle(
            &self,
            database: &mut NeighborhoodDatabase,
            gossip: &Gossip,
            gossip_source: IpAddr,
        ) -> GossipAcceptanceResult {
            self.handle_params.lock().unwrap().push((
                database.clone(),
                gossip.clone(),
                gossip_source,
            ));
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
            params_arc: &Arc<Mutex<Vec<(NeighborhoodDatabase, Gossip, IpAddr)>>>,
        ) -> GossipAcceptorMock {
            self.handle_params = params_arc.clone();
            self
        }

        pub fn handle_result(self, result: GossipAcceptanceResult) -> GossipAcceptorMock {
            self.handle_results.borrow_mut().push(result);
            self
        }
    }

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
    }

    impl GossipProducerMock {
        pub fn new() -> GossipProducerMock {
            GossipProducerMock {
                produce_params: Arc::new(Mutex::new(vec![])),
                produce_results: RefCell::new(vec![]),
            }
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
        expected = "A SubstratumNode without an --ip setting is not decentralized and cannot have any --neighbor settings"
    )]
    fn neighborhood_cannot_be_created_with_neighbors_and_default_ip() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let neighbor = make_node_record(1234, true, false);

        Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![(
                    neighbor.public_key().clone(),
                    neighbor.node_addr_opt().unwrap().clone(),
                )],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![0],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
        );
    }

    #[test]
    #[should_panic(
        expected = "A SubstratumNode without an --ip setting is not decentralized and cannot have any --port_count setting other than 0"
    )]
    fn neighborhood_cannot_be_created_with_clandestine_ports_and_default_ip() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));

        Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![1234],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
        );
    }

    #[test]
    #[should_panic(
        expected = "A SubstratumNode without an --ip setting is not decentralized and cannot be --node_type bootstrap"
    )]
    fn neighborhood_cannot_be_created_as_a_bootstrap_node_with_default_ip() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));

        Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: true,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
        );
    }

    #[test]
    #[should_panic(
        expected = "An --ip setting indicates that you want to decentralize, but you also need at least one --neighbor setting or --node_type bootstrap for that, and a --port_count greater than 0"
    )]
    fn neighborhood_cannot_be_created_with_ip_and_neighbors_but_no_clandestine_ports() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));

        Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str("2.3.4.5").unwrap(),
                clandestine_port_list: vec![0],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
        );
    }

    #[test]
    #[should_panic(
        expected = "An --ip setting indicates that you want to decentralize, but you also need at least one --neighbor setting or --node_type bootstrap for that, and a --port_count greater than 0"
    )]
    fn neighborhood_cannot_be_created_with_ip_and_clandestine_ports_but_no_neighbors() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));

        Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str("2.3.4.5").unwrap(),
                clandestine_port_list: vec![2345],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
        );
    }

    #[test]
    fn bootstrap_node_neighborhood_creates_single_node_database() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let this_node_addr = NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]);

        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: true,
                local_ip_addr: this_node_addr.ip_addr(),
                clandestine_port_list: this_node_addr.ports().clone(),
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
        );

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(root_node_record_ref.public_key(), &cryptde.public_key());
        assert_eq!(root_node_record_ref.node_addr_opt(), Some(this_node_addr));
        assert_eq!(root_node_record_ref.is_bootstrap_node(), true);
        assert_eq!(root_node_record_ref.half_neighbor_keys().len(), 0);
        assert_eq!(root_node_record_ref.consuming_wallet(), consuming_wallet);
    }

    #[test]
    fn bootstrap_node_with_no_neighbor_configs_ignores_bootstrap_neighborhood_now_message() {
        init_test_logging();
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("bootstrap_node_ignores_bootstrap_neighborhood_now_message");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: true,
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
        TestLogHandler::new().exists_log_containing(
            "INFO: Neighborhood: No bootstrap Nodes to report to; continuing",
        );
    }

    #[test]
    // TODO: This test will change drastically or disappear when Neighborhood bootstrapping is corrected.
    fn neighborhood_adds_nodes_and_links() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let one_bootstrap_node = make_node_record(3456, true, true);
        let another_bootstrap_node = make_node_record(4567, true, true);
        let this_node_addr = NodeAddr::new(&IpAddr::from_str("5.4.3.2").unwrap(), &vec![5678]);

        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![
                    (
                        one_bootstrap_node.public_key().clone(),
                        one_bootstrap_node.node_addr_opt().unwrap().clone(),
                    ),
                    (
                        another_bootstrap_node.public_key().clone(),
                        another_bootstrap_node.node_addr_opt().unwrap().clone(),
                    ),
                ],
                is_bootstrap_node: false,
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
        assert_eq!(root_node_record_ref.is_bootstrap_node(), false);

        assert_eq!(
            root_node_record_ref.has_half_neighbor(one_bootstrap_node.public_key()),
            true
        );
        assert_eq!(
            root_node_record_ref.has_half_neighbor(another_bootstrap_node.public_key()),
            true
        );

        assert_eq!(
            subject
                .neighborhood_database
                .node_by_key(one_bootstrap_node.public_key())
                .unwrap()
                .is_bootstrap_node(),
            true
        );
        assert_eq!(
            subject
                .neighborhood_database
                .node_by_key(another_bootstrap_node.public_key())
                .unwrap()
                .is_bootstrap_node(),
            true
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
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system =
            System::new("node_query_responds_with_none_when_key_query_matches_no_configured_data");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![(
                    PublicKey::new(&b"booga"[..]),
                    NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![1234, 2345]),
                )],
                is_bootstrap_node: false,
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
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system =
            System::new("node_query_responds_with_result_when_key_query_matches_configured_data");
        let one_neighbor = make_node_record(2345, true, false);
        let another_neighbor = make_node_record(3456, true, false);
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![node_record_to_pair(&one_neighbor)],
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec![5678],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
                rate_pack: rate_pack(100),
            },
        );
        subject
            .neighborhood_database
            .add_node(&another_neighbor)
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
            NodeDescriptor::new(
                another_neighbor.public_key().clone(),
                Some(another_neighbor.node_addr_opt().unwrap().clone()),
                another_neighbor.rate_pack().clone(),
            )
        );
    }

    #[test]
    fn node_query_responds_with_none_when_ip_address_query_matches_no_configured_data() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new(
            "node_query_responds_with_none_when_ip_address_query_matches_no_configured_data",
        );
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![(
                    PublicKey::new(&b"booga"[..]),
                    NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![1234, 2345]),
                )],
                is_bootstrap_node: false,
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
        let node_record = make_node_record(1234, true, false);
        let another_node_record = make_node_record(2345, true, false);
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![(
                    node_record.public_key().clone(),
                    node_record.node_addr_opt().unwrap().clone(),
                )],
                is_bootstrap_node: false,
                local_ip_addr: node_record.node_addr_opt().as_ref().unwrap().ip_addr(),
                clandestine_port_list: node_record
                    .node_addr_opt()
                    .as_ref()
                    .unwrap()
                    .ports()
                    .clone(),
                earning_wallet: node_record.earning_wallet(),
                consuming_wallet: node_record.consuming_wallet(),
                rate_pack: rate_pack(100),
            },
        );
        subject
            .neighborhood_database
            .add_node(&another_node_record)
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
            NodeDescriptor::new(
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
        let earning_wallet = Wallet::new("earning");
        let system = System::new(
            "route_query_succeeds_when_asked_for_one_hop_round_trip_route_without_consuming_wallet",
        );
        let mut subject = make_standard_subject();
        subject
            .neighborhood_database
            .root_mut()
            .set_wallets(earning_wallet, None);
        // These happen to be extracted in the desired order. We could not think of a way to guarantee it.
        let mut undesirable_exit_node = make_node_record(2345, true, false);
        let desirable_exit_node = make_node_record(3456, true, false);
        undesirable_exit_node.set_desirable(false);
        let originating_node = &subject.neighborhood_database.root().clone();
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(&undesirable_exit_node).unwrap();
            db.add_node(&desirable_exit_node).unwrap();
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
        assert_eq!(result, expected_response);
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_one_hop_round_trip_route_without_consuming_wallet_when_back_route_needs_two_hops(
    ) {
        let system = System::new("route_query_responds_with_none_when_asked_for_one_hop_round_trip_route_without_consuming_wallet_when_back_route_needs_two_hops");
        let mut subject = make_standard_subject();
        let a = &make_node_record(1234, true, false);
        let b = &subject.neighborhood_database.root().clone();
        let c = &make_node_record(3456, true, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(a).unwrap();
            db.add_node(c).unwrap();
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
            Database, where B is bootstrap and the rest are standard:

                 +---+-B-+---+
                 |   |   |   |
                 P---Q---R---S
                     |
                     T

            Tests will be written from the viewpoint of P.
    */

    #[test]
    fn route_query_messages() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("route_query_messages");
        let mut subject = make_standard_subject();
        subject
            .neighborhood_database
            .root_mut()
            .set_wallets(earning_wallet, consuming_wallet.clone());
        let b = &make_node_record(1234, true, true);
        let p = &subject.neighborhood_database.root().clone();
        let q = &make_node_record(3456, true, false);
        let r = &make_node_record(4567, false, false);
        let s = &make_node_record(5678, false, false);
        let mut t = make_node_record(1111, false, false);
        t.set_desirable(false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(b).unwrap();
            db.add_node(q).unwrap();
            db.add_node(&t).unwrap();
            db.add_node(r).unwrap();
            db.add_node(s).unwrap();
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| {
                db.add_arbitrary_full_neighbor(a.public_key(), b.public_key());
            };
            dual_edge(b, p);
            dual_edge(b, q);
            dual_edge(b, r);
            dual_edge(b, s);
            dual_edge(b, &t);
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
                consuming_wallet,
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
        assert_eq!(result, expected_response);
    }

    #[test]
    fn sort_routes_by_desirable_exit_nodes() {
        let mut subject = make_standard_subject();

        let us = subject.neighborhood_database.root().clone();
        let routing_node = make_node_record(0000, true, false);
        let desirable_node = make_node_record(1111, false, false);
        let mut undesirable_node = make_node_record(2222, false, false);
        undesirable_node.set_desirable(false);

        subject
            .neighborhood_database
            .add_node(&routing_node)
            .unwrap();
        subject
            .neighborhood_database
            .add_node(&undesirable_node)
            .unwrap();
        subject
            .neighborhood_database
            .add_node(&desirable_node)
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
            Database, where there is no bootstrap:

                 O---R---E

            Tests will be written from the viewpoint of O.
    */

    #[test]
    fn return_route_ids_increase() {
        let cryptde = cryptde();
        let system = System::new("return_route_ids_increase");
        let mut subject = make_standard_subject();
        let o = &subject.neighborhood_database.root().clone();
        let r = &make_node_record(4567, false, false);
        let e = &make_node_record(5678, false, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(r).unwrap();
            db.add_node(e).unwrap();
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
        let a = &make_node_record(3456, true, false);
        let db = &mut subject.neighborhood_database;
        db.add_node(a).unwrap();

        let result = subject.calculate_expected_service(a.public_key(), None, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "cannot calculate expected service, no keys provided in route segment"
        );
    }

    /*
            Database, where B is bootstrap and the rest are standard:

                B---+
                |   |
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
        let b = &db.add_node(&make_node_record(1234, true, true)).unwrap(); // AQIDBA
        let q = &db.add_node(&make_node_record(3456, true, false)).unwrap(); // AwQFBg
        let r = &db.add_node(&make_node_record(4567, true, false)).unwrap(); // BAUGBw
        let s = &db.add_node(&make_node_record(5678, true, false)).unwrap(); // BQYHCA
        let t = &db.add_node(&make_node_record(6789, true, false)).unwrap(); // BgcICQ
        db.add_arbitrary_full_neighbor(b, p);
        db.add_arbitrary_full_neighbor(b, r);
        db.add_arbitrary_full_neighbor(q, p);
        db.add_arbitrary_full_neighbor(p, r);
        db.add_arbitrary_full_neighbor(p, s);
        db.add_arbitrary_full_neighbor(t, s);
        db.add_arbitrary_full_neighbor(s, r);

        let contains = |routes: &Vec<Vec<&PublicKey>>, expected_keys: Vec<&PublicKey>| {
            assert_contains(&routes, &expected_keys);
        };

        // At least two hops from P to anywhere standard
        let routes = subject.complete_routes(vec![p], None, TargetType::Standard, 2);

        contains(&routes, vec![p, s, t]);
        contains(&routes, vec![p, r, s]);
        contains(&routes, vec![p, s, r]);
        assert_eq!(3, routes.len());

        // At least two hops from P to T
        let routes = subject.complete_routes(vec![p], Some(t), TargetType::Standard, 2);

        contains(&routes, vec![p, s, t]);
        contains(&routes, vec![p, r, s, t]);
        assert_eq!(2, routes.len());

        // At least two hops from P to B (bootstrap)
        let routes = subject.complete_routes(vec![p], Some(b), TargetType::Bootstrap, 2);

        // No routes are found, because bootstrap Nodes can't be exits
        assert_eq!(0, routes.len());

        // TODO: When the target_type parameter disappears, remove this section of the test
        // At least two hops from P to anywhere bootstrap
        let routes = subject.complete_routes(vec![p], None, TargetType::Bootstrap, 2);

        // No routes are found, because bootstrap Nodes can't be exits
        assert_eq!(0, routes.len());

        // At least two hops from P to S - one choice
        let routes = subject.complete_routes(vec![p], Some(s), TargetType::Standard, 2);

        contains(&routes, vec![p, r, s]);
        assert_eq!(1, routes.len());

        // At least two hops from P to Q - impossible
        let routes = subject.complete_routes(vec![p], Some(q), TargetType::Standard, 2);

        assert_eq!(0, routes.len());
    }

    #[test]
    fn gossips_after_removing_a_neighbor() {
        let (hopper, hopper_awaiter, hopper_recording) = make_recorder();
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            100,
            false,
        );
        let this_node_inside = this_node.clone();
        let removed_neighbor = make_node_record(2345, true, false);
        let removed_neighbor_inside = removed_neighbor.clone();
        let other_neighbor = make_node_record(3456, true, false);
        let other_neighbor_inside = other_neighbor.clone();

        thread::spawn(move || {
            let system = System::new("gossips_after_removing_a_neighbor");
            let mut subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![],
                    is_bootstrap_node: true,
                    local_ip_addr: this_node_inside.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: this_node_inside.node_addr_opt().unwrap().ports(),
                    earning_wallet: earning_wallet.clone(),
                    consuming_wallet: consuming_wallet.clone(),
                    rate_pack: rate_pack(100),
                },
            );
            let db = &mut subject.neighborhood_database;

            db.add_node(&removed_neighbor_inside).unwrap();
            db.add_node(&other_neighbor_inside).unwrap();
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
            let mut neighbors_vec = gnr
                .inner
                .neighbors
                .iter()
                .map(|k| k.clone())
                .collect::<Vec<PublicKey>>();
            neighbors_vec.sort_unstable_by(|a, b| a.cmp(&b));
            (
                gnr.public_key(),
                gnr.public_key().into(),
                gnr.inner.node_addr_opt.is_some(),
                gnr.inner.version,
                neighbors_vec,
            )
        };
        let mut digests = gossip
            .node_records
            .into_iter()
            .map(|nr| to_digest(nr))
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
        init_test_logging();
        let handle_params_arc = Arc::new(Mutex::new(vec![]));
        let gossip_acceptor = GossipAcceptorMock::new()
            .handle_params(&handle_params_arc)
            .handle_result(GossipAcceptanceResult::Ignored);
        let mut subject_node = make_cryptde_node_record(1234, true, false); // 9e7p7un06eHs6frl5A
        let bootstrap = make_node_record(1000, true, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&bootstrap));
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let gossip = GossipBuilder::new(&subject.neighborhood_database)
            .node(subject_node.public_key(), true)
            .build();
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor_ip: subject_node.node_addr_opt().unwrap().ip_addr(),
            consuming_wallet: None,
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
        let (call_database, call_gossip, call_gossip_source) = handle_params.remove(0);
        subject_node.add_half_neighbor_key(bootstrap.public_key().clone());
        assert!(handle_params.is_empty());
        assert_eq!(&subject_node, call_database.root());
        assert_eq!(2, call_database.keys().len());
        assert_eq!(gossip, call_gossip);
        assert_eq!(
            subject_node.node_addr_opt().unwrap().ip_addr(),
            call_gossip_source
        );
        TestLogHandler::new().exists_log_containing(
            format!(
                "INFO: Neighborhood: Ignored Gossip about 1 Nodes from {}",
                subject_node.public_key()
            )
            .as_str(),
        );
    }

    #[test]
    fn neighborhood_sends_only_acceptance_debuts_when_acceptance_debuts_are_provided() {
        init_test_logging();
        let introduction_target_node_1 = make_node_record(7345, true, false);
        let introduction_target_node_2 = make_node_record(7456, true, false);
        let subject_node = make_cryptde_node_record(5555, true, false); // 9e7p7un06eHs6frl5A
        let bootstrap = make_node_record(1000, true, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&bootstrap));
        subject
            .neighborhood_database
            .add_node(&introduction_target_node_1)
            .unwrap();
        subject
            .neighborhood_database
            .add_node(&introduction_target_node_2)
            .unwrap();
        subject.neighborhood_database.add_arbitrary_half_neighbor(
            subject_node.public_key(),
            introduction_target_node_1.public_key(),
        );
        subject.neighborhood_database.add_arbitrary_half_neighbor(
            subject_node.public_key(),
            introduction_target_node_2.public_key(),
        );
        let debut = GossipBuilder::new(&subject.neighborhood_database)
            .node(subject_node.public_key(), true)
            .build();
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Accepted(vec![
                (
                    debut.clone(),
                    introduction_target_node_1.public_key().clone(),
                    introduction_target_node_1.node_addr_opt().unwrap(),
                ),
                (
                    debut.clone(),
                    introduction_target_node_2.public_key().clone(),
                    introduction_target_node_2.node_addr_opt().unwrap(),
                ),
            ]));
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper_no_lookup = Some(peer_actors.hopper.from_hopper_client_no_lookup);

        subject.handle_gossip(
            &Gossip {
                node_records: vec![],
            },
            IpAddr::from_str("1.1.1.1").unwrap(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package_1 = hopper_recording.get_record::<NoLookupIncipientCoresPackage>(0);
        let package_2 = hopper_recording.get_record::<NoLookupIncipientCoresPackage>(1);
        assert_eq!(2, hopper_recording.len());
        assert_eq!(
            introduction_target_node_1.public_key(),
            &package_1.public_key
        );
        let gossip = match decodex::<MessageType>(
            &CryptDENull::from(introduction_target_node_1.public_key()),
            &package_1.payload,
        ) {
            Ok(MessageType::Gossip(g)) => g,
            x => panic!("Wanted Gossip, found {:?}", x),
        };
        assert_eq!(debut, gossip);
        assert_eq!(
            introduction_target_node_2.public_key(),
            &package_2.public_key
        );
        let gossip = match decodex::<MessageType>(
            &CryptDENull::from(introduction_target_node_2.public_key()),
            &package_2.payload,
        ) {
            Ok(MessageType::Gossip(g)) => g,
            x => panic!("Wanted Gossip, found {:?}", x),
        };
        assert_eq!(debut, gossip);
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            format!(
                "INFO: Neighborhood: Accepting introduction to Node {}/{}: sending debut",
                introduction_target_node_1.public_key(),
                introduction_target_node_1.node_addr_opt().unwrap()
            )
            .as_str(),
        );
        tlh.exists_log_containing(
            format!(
                "INFO: Neighborhood: Accepting introduction to Node {}/{}: sending debut",
                introduction_target_node_2.public_key(),
                introduction_target_node_2.node_addr_opt().unwrap()
            )
            .as_str(),
        );
    }

    #[test]
    fn neighborhood_sends_from_gossip_producer_when_acceptance_introductions_are_not_provided() {
        init_test_logging();
        let subject_node = make_cryptde_node_record(5555, true, false); // 9e7p7un06eHs6frl5A
        let bootstrap = make_node_record(1000, true, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&bootstrap));
        let full_neighbor = make_node_record(1234, true, false);
        let half_neighbor = make_node_record(2345, true, false);
        subject
            .neighborhood_database
            .add_node(&full_neighbor)
            .unwrap();
        subject
            .neighborhood_database
            .add_node(&half_neighbor)
            .unwrap();
        subject
            .neighborhood_database
            .add_arbitrary_full_neighbor(subject_node.public_key(), full_neighbor.public_key());
        subject
            .neighborhood_database
            .add_arbitrary_half_neighbor(subject_node.public_key(), half_neighbor.public_key());
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Accepted(vec![]));
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let gossip = Gossip {
            node_records: vec![],
        };
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
            &Gossip {
                node_records: vec![],
            },
            IpAddr::from_str("1.1.1.1").unwrap(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package_1 = hopper_recording.get_record::<IncipientCoresPackage>(0);
        let package_2 = hopper_recording.get_record::<IncipientCoresPackage>(1);
        let package_3 = hopper_recording.get_record::<IncipientCoresPackage>(2);
        fn digest(package: IncipientCoresPackage) -> (PublicKey, CryptData) {
            (
                package.route.next_hop(cryptde()).unwrap().public_key,
                package.payload,
            )
        }
        let digest_set = vec_to_set(vec![
            digest(package_1.clone()),
            digest(package_2.clone()),
            digest(package_3.clone()),
        ]);
        assert_eq!(
            vec_to_set(vec![
                (
                    bootstrap.public_key().clone(),
                    encodex(
                        cryptde(),
                        bootstrap.public_key(),
                        &MessageType::Gossip(gossip.clone())
                    )
                    .unwrap()
                ),
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
    }

    #[test]
    fn neighborhood_sends_only_relay_gossip_when_gossip_acceptor_relays() {
        init_test_logging();
        let subject_node = make_cryptde_node_record(5555, true, false); // 9e7p7un06eHs6frl5A
        let bootstrap = make_node_record(1000, true, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&bootstrap));
        let debut_node = make_node_record(1234, true, false);
        let debut_db = db_from_node(&debut_node);
        let gossip = GossipBuilder::new(&debut_db)
            .node(debut_node.public_key(), true)
            .build();
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Relay(
                gossip.clone(),
                subject_node.public_key().clone(),
                subject_node.node_addr_opt().unwrap(),
            ));
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let subject_node = subject.neighborhood_database.root().clone();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper_no_lookup = Some(peer_actors.hopper.from_hopper_client_no_lookup);

        subject.handle_gossip(
            &Gossip {
                node_records: vec![],
            },
            debut_node.node_addr_opt().unwrap().ip_addr(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        let package = hopper_recording.get_record::<NoLookupIncipientCoresPackage>(0);
        assert_eq!(1, hopper_recording.len());
        assert_eq!(subject_node.public_key(), &package.public_key);
        assert_eq!(
            gossip,
            match decodex::<MessageType>(
                &CryptDENull::from(subject_node.public_key()),
                &package.payload
            ) {
                Ok(MessageType::Gossip(g)) => g,
                x => panic!("Expected Gossip, but found {:?}", x),
            },
        );
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            format!(
                "INFO: Neighborhood: Relaying debut from Node {} to neighbor {}",
                debut_node.public_key(),
                subject_node.public_key()
            )
            .as_str(),
        );
    }

    #[test]
    fn neighborhood_sends_no_gossip_when_gossip_acceptor_ignores() {
        init_test_logging();
        let subject_node = make_cryptde_node_record(5555, true, false); // 9e7p7un06eHs6frl5A
        let bootstrap = make_node_record(1000, true, true);
        let mut subject = neighborhood_from_nodes(&subject_node, Some(&bootstrap));
        let gossip_acceptor =
            GossipAcceptorMock::new().handle_result(GossipAcceptanceResult::Ignored);
        subject.gossip_acceptor = Box::new(gossip_acceptor);
        let subject_node = subject.neighborhood_database.root().clone();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder().hopper(hopper).build();
        let system = System::new("");
        subject.hopper = Some(peer_actors.hopper.from_hopper_client);

        subject.handle_gossip(
            &Gossip {
                node_records: vec![],
            },
            subject_node.node_addr_opt().unwrap().ip_addr(),
        );

        System::current().stop();
        system.run();
        let hopper_recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(0, hopper_recording.len());
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing("INFO: Neighborhood: Ignored Gossip about 0 Nodes from 5.5.5.5");
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
        );
        let mut db = db_from_node(&this_node);
        let far_neighbor = make_node_record(1234, true, false);
        let gossip_neighbor = make_node_record(4567, true, false);
        db.add_node(&far_neighbor).unwrap();
        db.add_node(&gossip_neighbor).unwrap();
        db.add_arbitrary_full_neighbor(this_node.public_key(), gossip_neighbor.public_key());
        db.add_arbitrary_full_neighbor(gossip_neighbor.public_key(), far_neighbor.public_key());

        let gossip = GossipBuilder::new(&db)
            .node(gossip_neighbor.public_key(), true)
            .node(far_neighbor.public_key(), false)
            .build();
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            consuming_wallet: Some(Wallet::new("consuming")),
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
                    is_bootstrap_node: this_node_inside.is_bootstrap_node(),
                    local_ip_addr: this_node_inside.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: this_node_inside.node_addr_opt().unwrap().ports(),
                    earning_wallet: this_node_inside.earning_wallet(),
                    consuming_wallet: this_node_inside.consuming_wallet(),
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
        TestLogHandler::new()
            .await_log_containing(&format!("Finished processing Gossip about 2 Nodes"), 5000);

        TestLogHandler::new().exists_log_containing("Received Gossip: digraph db { ");
        TestLogHandler::new().exists_log_containing("\"AQIDBA\" [label=\"v0\\nAQIDBA\"];");
        TestLogHandler::new()
            .exists_log_containing("\"9e7p7un06eHs6frl5A\" [label=\"9e7p7un0\"] [shape=none];");
        TestLogHandler::new()
            .exists_log_containing("\"BAUGBw\" [label=\"v0\\nBAUGBw\\n4.5.6.7:4567\"];");
        TestLogHandler::new().exists_log_containing("\"AQIDBA\" -> \"BAUGBw\";");
        TestLogHandler::new().exists_log_containing("\"BAUGBw\" -> \"AQIDBA\";");
    }

    #[test]
    fn standard_node_requests_bootstrap_properly() {
        let cryptde = cryptde();
        let bootstrap_node = make_node_record(1234, true, true);
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let hopper_recording = hopper.get_recording();
        let bootstrap_node_inside = bootstrap_node.clone();
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![(
                    bootstrap_node_inside.public_key().clone(),
                    bootstrap_node_inside.node_addr_opt().unwrap().clone(),
                )],
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec![1234],
                earning_wallet: NodeRecord::earning_wallet_from_key(&cryptde.public_key()),
                consuming_wallet: NodeRecord::consuming_wallet_from_key(&cryptde.public_key()),
                rate_pack: rate_pack(100),
            },
        );
        thread::spawn(move || {
            let system = System::new("standard_node_requests_bootstrap_properly");
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
        let package_ref: &IncipientCoresPackage = locked_recording.get_record(0);
        check_direct_route_to(&package_ref.route, bootstrap_node.public_key());
        let bootstrap_node_cryptde = CryptDENull::from(bootstrap_node.public_key());
        let decrypted_payload = bootstrap_node_cryptde.decode(&package_ref.payload).unwrap();
        let gossip = match serde_cbor::de::from_slice(decrypted_payload.as_slice()).unwrap() {
            MessageType::Gossip(g) => g,
            x => panic!("Should have been MessageType::Gossip, but was {:?}", x),
        };
        let mut this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            100,
            false,
        );
        this_node.add_half_neighbor_key(bootstrap_node.public_key().clone());
        let expected_gnr = GossipNodeRecord {
            inner: NodeRecordInner {
                public_key: this_node.public_key().clone(),
                node_addr_opt: this_node.node_addr_opt(),
                earning_wallet: this_node.earning_wallet(),
                consuming_wallet: this_node.consuming_wallet(),
                rate_pack: rate_pack(100),
                is_bootstrap_node: this_node.is_bootstrap_node(),
                neighbors: vec_to_set(vec![bootstrap_node.public_key().clone()]),
                version: this_node.version(),
            },
            signatures: this_node.signatures().unwrap(),
        };
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
        let a = &make_node_record(3456, true, false);
        let b = &make_node_record(4567, false, false);
        let c = &make_node_record(5678, true, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(a).unwrap();
            db.add_node(b).unwrap();
            db.add_node(c).unwrap();
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
            target_type: TargetType::Standard,
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

    fn node_record_to_pair(node_record_ref: &NodeRecord) -> (PublicKey, NodeAddr) {
        (
            node_record_ref.public_key().clone(),
            node_record_ref.node_addr_opt().unwrap().clone(),
        )
    }

    fn check_direct_route_to(route: &Route, destination: &PublicKey) {
        let mut route = route.clone();
        let hop = route.shift(cryptde()).unwrap();
        assert_eq!(&hop.public_key, destination);
        assert_eq!(hop.component, Component::Hopper);
        let hop = route.shift(&CryptDENull::from(&destination)).unwrap();
        assert_eq!(hop.component, Component::Neighborhood);
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
                    endpoint: Endpoint::Key(cryptde.public_key()),
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
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new ("neighborhood_sends_node_query_response_with_none_when_key_query_matches_no_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();

            let subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![(
                        PublicKey::new(&b"booga"[..]),
                        NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![1234, 2345]),
                    )],
                    is_bootstrap_node: false,
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
                    endpoint: Endpoint::Key(cryptde.public_key()),
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
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        let one_neighbor = make_node_record(2345, true, false);
        let another_neighbor = make_node_record(3456, true, false);
        let another_neighbor_a = another_neighbor.clone();
        let context = TransmitDataMsg {
            endpoint: Endpoint::Key(cryptde.public_key()),
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
                    neighbor_configs: vec![node_record_to_pair(&one_neighbor)],
                    is_bootstrap_node: false,
                    local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                    clandestine_port_list: vec![5678],
                    earning_wallet: earning_wallet.clone(),
                    consuming_wallet: consuming_wallet.clone(),
                    rate_pack: rate_pack(100),
                },
            );
            subject
                .neighborhood_database
                .add_node(&another_neighbor)
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
            NodeDescriptor::new(
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
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("neighborhood_sends_node_query_response_with_none_when_ip_address_query_matches_no_configured_data");
            let addr: Addr<Recorder> = recorder.start();
            let recipient: Recipient<DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();
            let subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![(
                        PublicKey::new(&b"booga"[..]),
                        NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![1234, 2345]),
                    )],
                    is_bootstrap_node: false,
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
                    endpoint: Endpoint::Key(cryptde.public_key()),
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
        let node_record = make_node_record(1234, true, false);
        let another_node_record = make_node_record(2345, true, false);
        let another_node_record_a = another_node_record.clone();
        let context = TransmitDataMsg {
            endpoint: Endpoint::Key(cryptde.public_key()),
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
                    neighbor_configs: vec![(
                        node_record.public_key().clone(),
                        node_record.node_addr_opt().unwrap().clone(),
                    )],
                    is_bootstrap_node: false,
                    local_ip_addr: node_record.node_addr_opt().as_ref().unwrap().ip_addr(),
                    clandestine_port_list: node_record
                        .node_addr_opt()
                        .as_ref()
                        .unwrap()
                        .ports()
                        .clone(),
                    earning_wallet: node_record.earning_wallet(),
                    consuming_wallet: node_record.consuming_wallet(),
                    rate_pack: rate_pack(100),
                },
            );
            subject
                .neighborhood_database
                .add_node(&another_node_record_a)
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
            NodeDescriptor::new(
                another_node_record.public_key().clone(),
                Some(another_node_record.node_addr_opt().unwrap().clone()),
                another_node_record.rate_pack().clone(),
            )
        );
        assert_eq!(message.context, context_a);
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
