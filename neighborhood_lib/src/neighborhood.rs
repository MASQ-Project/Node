// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::gossip::to_dot_graph;
use crate::gossip::Gossip;
use crate::gossip_acceptor::GossipAcceptor;
use crate::gossip_acceptor::GossipAcceptorReal;
use crate::gossip_producer::GossipProducer;
use crate::gossip_producer::GossipProducerReal;
use crate::neighborhood_database::NeighborhoodDatabase;
use crate::neighborhood_database::NodeRecord;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::MessageResult;
use actix::Recipient;
use actix::Syn;
use sub_lib::accountant;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::PublicKey;
use sub_lib::dispatcher::Component;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::neighborhood::sentinel_ip_addr;
use sub_lib::neighborhood::BootstrapNeighborhoodNowMessage;
use sub_lib::neighborhood::DispatcherNodeQueryMessage;
use sub_lib::neighborhood::ExpectedService;
use sub_lib::neighborhood::NeighborhoodConfig;
use sub_lib::neighborhood::NeighborhoodSubs;
use sub_lib::neighborhood::NodeDescriptor;
use sub_lib::neighborhood::NodeQueryMessage;
use sub_lib::neighborhood::RemoveNeighborMessage;
use sub_lib::neighborhood::RouteQueryMessage;
use sub_lib::neighborhood::RouteQueryResponse;
use sub_lib::neighborhood::TargetType;
use sub_lib::node_addr::NodeAddr;
use sub_lib::peer_actors::BindMessage;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;
use sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use sub_lib::utils::plus;
use sub_lib::utils::NODE_MAILBOX_CAPACITY;

pub struct Neighborhood {
    cryptde: &'static dyn CryptDE,
    hopper: Option<Recipient<Syn, IncipientCoresPackage>>,
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
        ()
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
                    gossip.clone(),
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
        ()
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
        ()
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

impl Handler<ExpiredCoresPackage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackage, _ctx: &mut Self::Context) -> Self::Result {
        let incoming_gossip: Gossip = match msg.payload() {
            Ok(p) => p,
            Err(_) => {
                self.logger
                    .error(format!("Unintelligible Gossip message received: ignoring"));
                return ();
            }
        };
        self.logger.trace(format!(
            "Received Gossip: {}",
            to_dot_graph(
                incoming_gossip.clone(),
                self.neighborhood_database.root().public_key(),
                match self
                    .neighborhood_database
                    .node_by_ip(&msg.immediate_neighbor_ip)
                {
                    Some(node) => node.public_key().clone(),
                    None => PublicKey::new(&[]),
                }
            )
        ));
        let gossip_records = incoming_gossip.clone().node_records;
        let num_nodes = gossip_records.len();
        self.logger
            .info(format!("Processing Gossip about {} Nodes", num_nodes));

        let db_changed = self
            .gossip_acceptor
            .handle(&mut self.neighborhood_database, incoming_gossip);
        if db_changed {
            match gossip_records.as_slice() {
                [only] => self.gossip_to(&vec![only.public_key()]),
                _ => self.gossip_to_neighbors(),
            };
        }
        self.logger.info(format!(
            "Finished processing Gossip about {} Nodes",
            num_nodes
        ));
        ()
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
                    self.neighborhood_database.root_mut().increment_version();
                    self.gossip_to_neighbors();
                    self.logger
                        .info(format!("removed neighbor by public key: {}", public_key))
                }
            }
        }
        ()
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
            config.is_bootstrap_node,
            cryptde,
        );

        let add_node = |neighborhood_database: &mut NeighborhoodDatabase,
                        neighbor: &(PublicKey, NodeAddr),
                        is_bootstrap_node: bool| {
            let (key, node_addr) = neighbor;
            let root_key_ref = &neighborhood_database.root().public_key().clone();
            neighborhood_database
                .add_node(&NodeRecord::new(
                    &key,
                    Some(&node_addr),
                    accountant::DEFAULT_EARNING_WALLET.clone(),
                    None,
                    is_bootstrap_node,
                    None,
                    0,
                ))
                .expect(&format!("Database already contains node {:?}", key));
            neighborhood_database
                .add_neighbor(root_key_ref, &key)
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
            gossip_acceptor,
            gossip_producer,
            neighborhood_database,
            next_return_route_id: 0,
            logger: Logger::new("Neighborhood"),
        }
    }

    fn gossip_to_neighbors(&self) {
        self.gossip_to(self.neighborhood_database.root().neighbors());
    }

    fn gossip_to(&self, neighbors: &Vec<PublicKey>) {
        neighbors.iter().for_each(|neighbor| {
            let gossip = self
                .gossip_producer
                .produce(&self.neighborhood_database, neighbor);
            let gossip_len = gossip.node_records.len();
            let route = self.create_single_hop_route(neighbor);
            let package = IncipientCoresPackage::new(self.cryptde, route, gossip, neighbor)
                .expect("Key magically disappeared");
            self.logger.info(format!(
                "Relaying Gossip about {} nodes to {}",
                gossip_len, neighbor
            ));
            self.hopper
                .as_ref()
                .expect("unbound hopper")
                .try_send(package)
                .expect("hopper is dead");
        });
    }

    pub fn make_subs_from(addr: &Addr<Syn, Neighborhood>) -> NeighborhoodSubs {
        NeighborhoodSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            bootstrap: addr.clone().recipient::<BootstrapNeighborhoodNowMessage>(),
            node_query: addr.clone().recipient::<NodeQueryMessage>(),
            route_query: addr.clone().recipient::<RouteQueryMessage>(),
            from_hopper: addr.clone().recipient::<ExpiredCoresPackage>(),
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
            expected_services: vec![ExpectedService::Nothing, ExpectedService::Nothing],
            return_route_id: return_route_id,
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
        let mut segments = vec![over, back];

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
        let return_route_id = self.advance_return_route_id();

        let expected_routing_services = self.make_expected_services(&segments);
        expected_routing_services.map(|expected_services| RouteQueryResponse {
            route: Route::round_trip(
                segments.remove(0),
                segments.remove(0),
                self.cryptde,
                consuming_wallet_opt,
                return_route_id,
            )
            .expect("Internal error: bad route"),
            expected_services,
            return_route_id,
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
            let chosen_node_seq = node_seqs.remove(0);
            Ok(RouteSegment::new(chosen_node_seq, target_component))
        }
    }

    fn make_expected_services(
        &self,
        segments: &Vec<RouteSegment>,
    ) -> Result<Vec<ExpectedService>, String> {
        let request_segment_keys = match segments.first() {
            Some(segment) => segment.keys.clone(),
            None => return Err("Cannot make multi-hop route without segments".to_string()),
        };
        let expected_services: Result<Vec<ExpectedService>, String> = request_segment_keys
            .iter()
            .map(|ref key| {
                self.calculate_expected_routing_service(
                    key,
                    request_segment_keys.first(),
                    request_segment_keys.last(),
                )
            })
            .collect();

        expected_services
    }

    fn calculate_expected_routing_service(
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
                            ))
                        }
                        (Some(_), Some(_)) => Ok(ExpectedService::Routing(
                            route_segment_key.clone(),
                            node.earning_wallet(),
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
        target_type: TargetType,
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
                .neighbors()
                .iter()
                .filter(|neighbor_key_ref_ref| !prefix.contains(neighbor_key_ref_ref))
                .flat_map(|neighbor_key_ref_ref| {
                    let mut new_prefix = prefix.clone();
                    new_prefix.push(neighbor_key_ref_ref);
                    self.complete_routes(
                        new_prefix.clone(),
                        target,
                        target_type,
                        if hops_remaining == 0 {
                            0
                        } else {
                            hops_remaining - 1
                        },
                    )
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::GossipBuilder;
    use crate::gossip::GossipNodeRecord;
    use crate::neighborhood_test_utils::make_node_record;
    use actix::msgs;
    use actix::Arbiter;
    use actix::Recipient;
    use actix::System;
    use serde_cbor;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::thread;
    use sub_lib::cryptde::PlainData;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::dispatcher::Endpoint;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::neighborhood::sentinel_ip_addr;
    use sub_lib::stream_handler_pool::TransmitDataMsg;
    use sub_lib::wallet::Wallet;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::recorder::make_recorder;
    use test_utils::recorder::Recorder;
    use test_utils::recorder::Recording;
    use test_utils::tcp_wrapper_mocks::TcpStreamWrapperFactoryMock;
    use test_utils::tcp_wrapper_mocks::TcpStreamWrapperMock;
    use test_utils::test_utils::assert_contains;
    use test_utils::test_utils::cryptde;
    use test_utils::test_utils::make_meaningless_route;
    use tokio::prelude::Future;

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
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
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
        let neighbor = make_node_record(1234, true, false);

        Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![(
                    neighbor.public_key().clone(),
                    neighbor.node_addr_opt().unwrap().clone(),
                )],
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str("2.3.4.5").unwrap(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
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
            },
        );

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(root_node_record_ref.public_key(), &cryptde.public_key());
        assert_eq!(root_node_record_ref.node_addr_opt(), Some(this_node_addr));
        assert_eq!(root_node_record_ref.is_bootstrap_node(), true);
        assert_eq!(root_node_record_ref.neighbors().len(), 0);
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
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, BootstrapNeighborhoodNowMessage> =
            addr.clone().recipient::<BootstrapNeighborhoodNowMessage>();
        let (hopper, _, hopper_recording_arc) = make_recorder();
        let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None, None, None);
        addr.try_send(BindMessage { peer_actors }).unwrap();

        sub.try_send(BootstrapNeighborhoodNowMessage {}).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let recording = hopper_recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 0);
        TestLogHandler::new().exists_log_containing(
            "INFO: Neighborhood: No bootstrap Nodes to report to; continuing",
        );
    }

    #[test]
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
            },
        );

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(
            root_node_record_ref.node_addr_opt().unwrap().clone(),
            this_node_addr
        );
        assert_eq!(root_node_record_ref.is_bootstrap_node(), false);

        assert_eq!(
            root_node_record_ref.has_neighbor(one_bootstrap_node.public_key()),
            true
        );
        assert_eq!(
            root_node_record_ref.has_neighbor(another_bootstrap_node.public_key()),
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
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("responds_with_none_when_initially_configured_with_no_data");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::PublicKey(PublicKey::new(&b"booga"[..])));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn node_query_responds_with_none_when_key_query_matches_no_configured_data() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("responds_with_none_when_initially_configured_with_no_data");
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
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::PublicKey(PublicKey::new(&b"blah"[..])));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn node_query_responds_with_result_when_key_query_matches_configured_data() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("responds_with_none_when_initially_configured_with_no_data");
        let one_neighbor = make_node_record(2345, true, false);
        let another_neighbor = make_node_record(3456, true, false);
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![
                    node_record_to_pair(&one_neighbor),
                    node_record_to_pair(&another_neighbor),
                ],
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec![5678],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::PublicKey(
            another_neighbor.public_key().clone(),
        ));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(
            result.unwrap(),
            NodeDescriptor::new(
                another_neighbor.public_key().clone(),
                Some(another_neighbor.node_addr_opt().unwrap().clone())
            )
        );
    }

    #[test]
    fn node_query_responds_with_none_when_ip_address_query_matches_no_configured_data() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("responds_with_none_when_initially_configured_with_no_data");
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
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::IpAddress(
            IpAddr::from_str("2.3.4.5").unwrap(),
        ));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn node_query_responds_with_result_when_ip_address_query_matches_configured_data() {
        let cryptde = cryptde();
        let system = System::new("responds_with_none_when_initially_configured_with_no_data");
        let node_record = make_node_record(1234, true, false);
        let another_node_record = make_node_record(2345, true, false);
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![
                    (
                        node_record.public_key().clone(),
                        node_record.node_addr_opt().unwrap().clone(),
                    ),
                    (
                        another_node_record.public_key().clone(),
                        another_node_record.node_addr_opt().unwrap().clone(),
                    ),
                ],
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
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, NodeQueryMessage> = addr.recipient::<NodeQueryMessage>();

        let future = sub.send(NodeQueryMessage::IpAddress(
            IpAddr::from_str("1.2.3.4").unwrap(),
        ));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(
            result.unwrap(),
            NodeDescriptor::new(
                node_record.public_key().clone(),
                Some(node_record.node_addr_opt().unwrap().clone())
            )
        );
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_route_with_too_many_hops() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("responds_with_none_when_asked_for_route_with_empty_database");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let future = sub.send(RouteQueryMessage::data_indefinite_route_request(5));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_two_hop_round_trip_route_without_consuming_wallet(
    ) {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let system = System::new("responds_with_none_when_asked_for_route_with_empty_database");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: None,
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let future = sub.send(RouteQueryMessage::data_indefinite_route_request(2));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
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
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: None,
            },
        );
        let a = &make_node_record(1234, true, false);
        let b = &subject.neighborhood_database.root().clone();
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(a).unwrap();
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| dual_edge_func(db, a, b);
            dual_edge(a, b);
        }
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();
        let msg = RouteQueryMessage::data_indefinite_route_request(1);

        let future = sub.send(msg);

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
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
                segment(vec![b, a], Component::ProxyClient),
                segment(vec![a, b], Component::ProxyServer),
                cryptde,
                None,
                0,
            )
            .unwrap(),
            expected_services: vec![
                ExpectedService::Nothing,
                ExpectedService::Exit(a.public_key().clone(), a.earning_wallet()),
            ],
            return_route_id: 0,
        };
        assert_eq!(result, expected_response);
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_one_hop_round_trip_route_without_consuming_wallet_when_back_route_needs_two_hops(
    ) {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let system = System::new("route_query_responds_with_none_when_asked_for_one_hop_round_trip_route_without_consuming_wallet_when_back_route_needs_two_hops");
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: None,
            },
        );
        let a = &make_node_record(1234, true, false);
        let b = &subject.neighborhood_database.root().clone();
        let c = &make_node_record(3456, true, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(a).unwrap();
            db.add_node(c).unwrap();
            let mut single_edge = |a: &NodeRecord, b: &NodeRecord| single_edge_func(db, a, b);
            single_edge(a, b);
            single_edge(b, c);
            single_edge(c, a);
        }
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();
        let msg = RouteQueryMessage::data_indefinite_route_request(1);

        let future = sub.send(msg);

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_two_hop_one_way_route_without_consuming_wallet(
    ) {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let system = System::new("route_query_responds_with_none_when_asked_for_two_hop_one_way_route_without_consuming_wallet");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: None,
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();
        let msg = RouteQueryMessage::data_indefinite_route_request(2);

        let future = sub.send(msg);

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let result = future.wait().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn route_query_responds_with_standard_zero_hop_route_when_requested() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("responds_with_standard_zero_hop_route_when_requested");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let future = sub.send(RouteQueryMessage::data_indefinite_route_request(0));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
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
            expected_services: vec![ExpectedService::Nothing, ExpectedService::Nothing],
            return_route_id: 0,
        };
        assert_eq!(result, expected_response);
    }

    #[test]
    fn zero_hop_routing_handles_return_route_id_properly() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: None,
            },
        );

        let result0 = subject.zero_hop_route_response();
        let result1 = subject.zero_hop_route_response();

        assert_eq!(result0.return_route_id, 0);
        assert_eq!(result1.return_route_id, 1);
    }

    /*
            Database, where B is bootstrap and the rest are standard:

                 +---+-B-+---+
                 |   |   |   |
                 P---Q---R---S

            Tests will be written from the viewpoint of P.
    */

    #[test]
    fn route_query_messages() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("route_query_messages");
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );
        let b = &make_node_record(1234, true, true);
        let p = &subject.neighborhood_database.root().clone();
        let q = &make_node_record(3456, true, false);
        let r = &make_node_record(4567, false, false);
        let s = &make_node_record(5678, false, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(b).unwrap();
            db.add_node(q).unwrap();
            db.add_node(r).unwrap();
            db.add_node(s).unwrap();
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| dual_edge_func(db, a, b);
            dual_edge(b, p);
            dual_edge(b, q);
            dual_edge(b, r);
            dual_edge(b, s);
            dual_edge(p, q);
            dual_edge(q, r);
            dual_edge(r, s);
        }

        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let data_route = sub.send(RouteQueryMessage::data_indefinite_route_request(2));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
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
            expected_services: vec![
                ExpectedService::Nothing,
                ExpectedService::Routing(q.public_key().clone(), q.earning_wallet()),
                ExpectedService::Exit(r.public_key().clone(), r.earning_wallet()),
            ],
            return_route_id: 0,
        };
        assert_eq!(result, expected_response);
    }

    #[test]
    fn compose_route_query_response_returns_an_error_when_route_segment_is_empty() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );

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
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: None,
            },
        );
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
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("return_route_ids_increase");
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );
        let o = &subject.neighborhood_database.root().clone();
        let r = &make_node_record(4567, false, false);
        let e = &make_node_record(5678, false, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(r).unwrap();
            db.add_node(e).unwrap();
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| dual_edge_func(db, a, b);
            dual_edge(o, r);
            dual_edge(r, e);
        }

        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage>();

        let data_route_0 = sub.send(RouteQueryMessage::data_indefinite_route_request(2));
        let data_route_1 = sub.send(RouteQueryMessage::data_indefinite_route_request(2));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        let result_0 = data_route_0.wait().unwrap().unwrap();
        let result_1 = data_route_1.wait().unwrap().unwrap();
        let juicy_parts = |result: RouteQueryResponse| {
            let last_element = result.route.hops.last().unwrap();
            let last_element_dec = cryptde.decode(last_element).unwrap();
            let network_return_route_id: u32 =
                serde_cbor::de::from_slice(last_element_dec.as_slice()).unwrap();
            let metadata_return_route_id = result.return_route_id;
            (network_return_route_id, metadata_return_route_id)
        };
        assert_eq!(juicy_parts(result_0), (0, 0));
        assert_eq!(juicy_parts(result_1), (1, 1));
    }

    #[test]
    fn compose_route_query_response_returns_an_error_when_route_segment_keys_is_empty() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );

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
        let cryptde = cryptde();
        let consuming_wallet = Some(Wallet::new("consuming"));
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: Wallet::new(""),
                consuming_wallet: consuming_wallet.clone(),
            },
        );

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
    }

    #[test]
    fn calculate_expected_routing_service_returns_error_when_given_empty_segment() {
        let cryptde = cryptde();
        let consuming_wallet = Some(Wallet::new("consuming"));
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: Wallet::new(""),
                consuming_wallet: consuming_wallet.clone(),
            },
        );

        let a = &make_node_record(3456, true, false);
        let db = &mut subject.neighborhood_database;
        db.add_node(a).unwrap();

        let result = subject.calculate_expected_routing_service(a.public_key(), None, None);
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
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let mut subject = Neighborhood::new(
            cryptde(),
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );
        let b = &make_node_record(1234, true, true);
        let p = &subject.neighborhood_database.root().clone();
        let q = &make_node_record(3456, true, false);
        let r = &make_node_record(4567, false, false);
        let s = &make_node_record(5678, false, false);
        let t = &make_node_record(6789, false, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(b).unwrap();
            db.add_node(q).unwrap();
            db.add_node(r).unwrap();
            db.add_node(s).unwrap();
            db.add_node(t).unwrap();
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| dual_edge_func(db, a, b);
            dual_edge(b, p);
            dual_edge(b, r);
            dual_edge(q, p);
            dual_edge(p, r);
            dual_edge(p, s);
            dual_edge(t, s);
            dual_edge(s, r);
        }

        let contains = |routes: &Vec<Vec<&PublicKey>>, expected_nodes: Vec<&NodeRecord>| {
            let expected_keys: Vec<&PublicKey> =
                expected_nodes.into_iter().map(|n| n.public_key()).collect();
            assert_contains(&routes, &expected_keys);
        };

        // At least two hops from P to anywhere standard
        let routes = subject.complete_routes(vec![p.public_key()], None, TargetType::Standard, 2);

        contains(&routes, vec![p, s, t]);
        contains(&routes, vec![p, r, s]);
        contains(&routes, vec![p, s, r]);
        assert_eq!(routes.len(), 3);

        // At least two hops from P to T
        let routes = subject.complete_routes(
            vec![p.public_key()],
            Some(t.public_key()),
            TargetType::Standard,
            2,
        );

        contains(&routes, vec![p, s, t]);
        contains(&routes, vec![p, r, s, t]);
        assert_eq!(routes.len(), 2);

        // At least two hops from P to B (bootstrap)
        let routes = subject.complete_routes(
            vec![p.public_key()],
            Some(b.public_key()),
            TargetType::Bootstrap,
            2,
        );

        contains(&routes, vec![p, r, b]);
        contains(&routes, vec![p, s, r, b]);
        assert_eq!(routes.len(), 2);

        // At least two hops from P to anywhere bootstrap
        let routes = subject.complete_routes(vec![p.public_key()], None, TargetType::Bootstrap, 2);

        contains(&routes, vec![p, r, b]);
        contains(&routes, vec![p, s, r, b]);
        assert_eq!(routes.len(), 2);

        // At least two hops from P to S - one choice
        let routes = subject.complete_routes(
            vec![p.public_key()],
            Some(s.public_key()),
            TargetType::Standard,
            2,
        );

        contains(&routes, vec![p, r, s]);
        assert_eq!(routes.len(), 1);

        // At least two hops from P to Q - impossible
        let routes = subject.complete_routes(
            vec![p.public_key()],
            Some(q.public_key()),
            TargetType::Standard,
            2,
        );

        assert_eq!(routes.len(), 0);

        // At least two hops from P to R (bootstrap) - impossible
        let routes = subject.complete_routes(
            vec![p.public_key()],
            Some(r.public_key()),
            TargetType::Bootstrap,
            2,
        );

        assert_eq!(routes.len(), 0);
    }

    #[test]
    fn bad_cores_package_is_logged_and_ignored() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        init_test_logging();
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            consuming_wallet: Some(Wallet::new("consuming")),
            remaining_route: make_meaningless_route(),
            payload: PlainData::new(&b"booga"[..]),
        };
        let system = System::new("");
        let subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );
        let addr: Addr<Syn, Neighborhood> = subject.start();
        let sub: Recipient<Syn, ExpiredCoresPackage> = addr.recipient::<ExpiredCoresPackage>();

        sub.try_send(cores_package).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "ERROR: Neighborhood: Unintelligible Gossip message received: ignoring",
        );
    }

    #[test]
    fn gossips_after_removing_a_neighbor() {
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let hopper_recording = hopper.get_recording();
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            true,
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
                    is_bootstrap_node: this_node_inside.is_bootstrap_node(),
                    local_ip_addr: this_node_inside.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: this_node_inside.node_addr_opt().unwrap().ports(),
                    earning_wallet: earning_wallet.clone(),
                    consuming_wallet: consuming_wallet.clone(),
                },
            );

            subject
                .neighborhood_database
                .add_node(&removed_neighbor_inside)
                .unwrap();
            subject
                .neighborhood_database
                .add_node(&other_neighbor_inside)
                .unwrap();
            subject
                .neighborhood_database
                .add_neighbor(&cryptde.public_key(), removed_neighbor_inside.public_key())
                .unwrap();
            subject
                .neighborhood_database
                .add_neighbor(&cryptde.public_key(), other_neighbor_inside.public_key())
                .unwrap();

            let addr: Addr<Syn, Neighborhood> = subject.start();
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub: Recipient<Syn, RemoveNeighborMessage> =
                addr.recipient::<RemoveNeighborMessage>();
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
        let decrypted_payload = other_neighbor_cryptde.decode(&package.payload).unwrap();
        let gossip: Gossip = serde_cbor::de::from_slice(decrypted_payload.as_slice()).unwrap();
        let the_node_record = gossip
            .node_records
            .iter()
            .find(|&x| x.inner.public_key == cryptde.public_key())
            .expect("should have the node record");
        assert!(!the_node_record
            .inner
            .neighbors
            .contains(&removed_neighbor.public_key()));
    }

    #[test]
    fn neighborhood_sends_gossip_when_db_changes() {
        let cryptde = cryptde();
        let mut this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            true,
        );
        let mut gossip_neighbor = make_node_record(4567, true, false);
        gossip_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        let gossip = GossipBuilder::new().node(&gossip_neighbor, true).build();
        let serialized_gossip = PlainData::new(&serde_cbor::ser::to_vec(&gossip).unwrap()[..]);
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            consuming_wallet: Some(Wallet::new("consuming")),
            remaining_route: make_meaningless_route(),
            payload: serialized_gossip,
        };
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let hopper_recording = hopper.get_recording();
        let this_node_inside = this_node.clone();
        thread::spawn(move || {
            let system = System::new("");
            let mut subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![],
                    is_bootstrap_node: this_node_inside.is_bootstrap_node(),
                    local_ip_addr: this_node_inside.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: this_node_inside.node_addr_opt().unwrap().ports(),
                    earning_wallet: this_node_inside.earning_wallet(),
                    consuming_wallet: this_node_inside.consuming_wallet(),
                },
            );

            let mut gossip_acceptor = GossipAcceptorReal::new();
            gossip_acceptor.tcp_stream_factory = Box::new(
                TcpStreamWrapperFactoryMock::new()
                    .tcp_stream_wrapper(TcpStreamWrapperMock::new().connect_result(Ok(()))),
            );
            subject.gossip_acceptor = Box::new(gossip_acceptor);

            let addr: Addr<Syn, Neighborhood> = subject.start();
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub: Recipient<Syn, ExpiredCoresPackage> = addr.recipient::<ExpiredCoresPackage>();
            sub.try_send(cores_package).unwrap();

            system.run();
        });
        hopper_awaiter.await_message_count(1);
        let locked_recording = hopper_recording.lock().unwrap();
        let package = locked_recording.get_record(0);
        // Now make this_node look the way subject's initial NodeRecord will have looked after receiving the Gossip, so that
        // it appears correct for checking the gossip contents.
        this_node
            .neighbors_mut()
            .push(gossip_neighbor.public_key().clone());
        this_node.increment_version();

        assert_eq!(&find_package_target(package), gossip_neighbor.public_key());
        check_direct_route_to(&package.route, gossip_neighbor.public_key());
        let gossip_neighbor_cryptde = CryptDENull::from(gossip_neighbor.public_key());
        let decrypted_payload = gossip_neighbor_cryptde.decode(&package.payload).unwrap();
        let gossip: Gossip = serde_cbor::de::from_slice(decrypted_payload.as_slice()).unwrap();
        assert_eq!(gossip.node_records.len(), 2);
        let gossip_node_records = gossip.node_records;
        assert_contains(
            &gossip_node_records,
            &GossipNodeRecord::from(&gossip_neighbor, false),
        );
        assert_contains(
            &gossip_node_records,
            &GossipNodeRecord::from(&this_node, true),
        );
    }

    #[test]
    fn standard_node_requests_bootstrap_properly() {
        let cryptde = cryptde();
        let bootstrap_node = make_node_record(1234, true, true);
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let hopper_recording = hopper.get_recording();
        let bootstrap_node_inside = bootstrap_node.clone();
        thread::spawn(move || {
            let system = System::new("standard_node_requests_bootstrap_properly");
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
                },
            );
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub: Recipient<Syn, BootstrapNeighborhoodNowMessage> =
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
        let gossip: Gossip = serde_cbor::de::from_slice(decrypted_payload.as_slice()).unwrap();
        let mut this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            false,
        );
        this_node
            .neighbors_mut()
            .push(bootstrap_node.public_key().clone());
        assert_contains(
            &gossip.node_records,
            &GossipNodeRecord::from(&this_node, true),
        );
        assert_eq!(gossip.node_records.len(), 1);
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
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let system = System::new("neighborhood_removes_neighbor_when_directed_to");
        let hopper = Recorder::new();
        let mut subject = Neighborhood::new(
            cryptde,
            NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr(),
                clandestine_port_list: vec![],
                earning_wallet: earning_wallet.clone(),
                consuming_wallet: consuming_wallet.clone(),
            },
        );
        let n = &subject.neighborhood_database.root().clone();
        let a = &make_node_record(3456, true, false);
        let b = &make_node_record(4567, false, false);
        let c = &make_node_record(5678, true, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(a).unwrap();
            db.add_node(b).unwrap();
            db.add_node(c).unwrap();
            let mut edge = |a: &NodeRecord, b: &NodeRecord| single_edge_func(db, a, b);
            edge(n, a);
            edge(n, c);
            edge(a, b);
            edge(b, a);
            edge(b, c);
            edge(c, b);
        }

        let addr: Addr<Syn, Neighborhood> = subject.start();
        let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None, None, None);
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
        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();

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

    fn find_package_target(package: &IncipientCoresPackage) -> PublicKey {
        let mut route = package.route.clone();
        let hop = route.shift(cryptde()).unwrap();
        hop.public_key
    }

    fn check_direct_route_to(route: &Route, destination: &PublicKey) {
        let mut route = route.clone();
        let hop = route.shift(cryptde()).unwrap();
        assert_eq!(&hop.public_key, destination);
        assert_eq!(hop.component, Component::Hopper);
        let hop = route.shift(&CryptDENull::from(&destination)).unwrap();
        assert_eq!(hop.component, Component::Neighborhood);
    }

    fn dual_edge_func(db: &mut NeighborhoodDatabase, a: &NodeRecord, b: &NodeRecord) {
        db.add_neighbor(a.public_key(), b.public_key()).unwrap();
        db.add_neighbor(b.public_key(), a.public_key()).unwrap();
    }

    fn single_edge_func(db: &mut NeighborhoodDatabase, a: &NodeRecord, b: &NodeRecord) {
        db.add_neighbor(a.public_key(), b.public_key()).unwrap();
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_none_when_initially_configured_with_no_data() {
        let cryptde = cryptde();
        let earning_wallet = Wallet::new("earning");
        let consuming_wallet = Some(Wallet::new("consuming"));
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("responds_with_none_when_initially_configured_with_no_data");

            let addr: Addr<Syn, Recorder> = recorder.start();
            let recipient: Recipient<Syn, DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();

            let subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![],
                    is_bootstrap_node: false,
                    local_ip_addr: sentinel_ip_addr(),
                    clandestine_port_list: vec![],
                    earning_wallet: earning_wallet.clone(),
                    consuming_wallet: consuming_wallet.clone(),
                },
            );
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let sub: Recipient<Syn, DispatcherNodeQueryMessage> =
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
            let addr: Addr<Syn, Recorder> = recorder.start();
            let recipient: Recipient<Syn, DispatcherNodeQueryResponse> =
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
                },
            );
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let sub: Recipient<Syn, DispatcherNodeQueryMessage> =
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
            let addr: Addr<Syn, Recorder> = recorder.start();
            let recipient = addr.recipient::<DispatcherNodeQueryResponse>();
            let subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![
                        node_record_to_pair(&one_neighbor),
                        node_record_to_pair(&another_neighbor),
                    ],
                    is_bootstrap_node: false,
                    local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                    clandestine_port_list: vec![5678],
                    earning_wallet: earning_wallet.clone(),
                    consuming_wallet: consuming_wallet.clone(),
                },
            );
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let sub: Recipient<Syn, DispatcherNodeQueryMessage> =
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
                Some(another_neighbor_a.node_addr_opt().unwrap().clone())
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
            let system = System::new("responds_with_none_when_initially_configured_with_no_data");
            let addr: Addr<Syn, Recorder> = recorder.start();
            let recipient: Recipient<Syn, DispatcherNodeQueryResponse> =
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
                },
            );
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let sub: Recipient<Syn, DispatcherNodeQueryMessage> =
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
        let node_record_a = node_record.clone();
        let context = TransmitDataMsg {
            endpoint: Endpoint::Key(cryptde.public_key()),
            last_data: false,
            sequence_number: None,
            data: Vec::new(),
        };
        let context_a = context.clone();
        thread::spawn(move || {
            let system = System::new("responds_with_none_when_initially_configured_with_no_data");
            let addr: Addr<Syn, Recorder> = recorder.start();
            let recipient: Recipient<Syn, DispatcherNodeQueryResponse> =
                addr.recipient::<DispatcherNodeQueryResponse>();
            let another_node_record = make_node_record(2345, true, false);
            let subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![
                        (
                            node_record.public_key().clone(),
                            node_record.node_addr_opt().unwrap().clone(),
                        ),
                        (
                            another_node_record.public_key().clone(),
                            another_node_record.node_addr_opt().unwrap().clone(),
                        ),
                    ],
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
                },
            );
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let sub: Recipient<Syn, DispatcherNodeQueryMessage> =
                addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::IpAddress(IpAddr::from_str("1.2.3.4").unwrap()),
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
                node_record_a.public_key().clone(),
                Some(node_record_a.node_addr_opt().unwrap().clone())
            )
        );
        assert_eq!(message.context, context_a);
    }

    #[test]
    fn neighborhood_does_not_gossip_when_db_does_not_change() {
        init_test_logging();
        let cryptde = cryptde();
        let bootstrap_node = make_node_record(5648, true, true);
        let this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            false,
        );
        let mut one_neighbor = make_node_record(2345, true, false);
        one_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        let gossip = GossipBuilder::new().node(&one_neighbor, true).build();
        let serialized_gossip = PlainData::new(&serde_cbor::ser::to_vec(&gossip).unwrap()[..]);
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            consuming_wallet: Some(Wallet::new("consuming")),
            remaining_route: make_meaningless_route(),
            payload: serialized_gossip,
        };
        let hopper = Recorder::new();
        let hopper_recording = hopper.get_recording();
        thread::spawn(move || {
            let system = System::new("");
            let mut subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![(
                        bootstrap_node.public_key().clone(),
                        bootstrap_node.node_addr_opt().unwrap(),
                    )],
                    is_bootstrap_node: false,
                    local_ip_addr: this_node.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: this_node.node_addr_opt().unwrap().ports(),
                    earning_wallet: this_node.earning_wallet(),
                    consuming_wallet: this_node.consuming_wallet(),
                },
            );
            subject
                .neighborhood_database
                .add_node(&one_neighbor)
                .unwrap();
            subject
                .neighborhood_database
                .add_neighbor(this_node.public_key(), one_neighbor.public_key())
                .unwrap();
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub: Recipient<Syn, ExpiredCoresPackage> = addr.recipient::<ExpiredCoresPackage>();
            sub.try_send(cores_package).unwrap();

            system.run();
        });
        TestLogHandler::new()
            .await_log_containing(&format!("Finished processing Gossip about 1 Nodes"), 5000);
        let locked_recording = hopper_recording.lock().unwrap();
        assert_eq!(0, locked_recording.len());
    }

    #[test]
    fn node_gossips_only_to_immediate_neighbors() {
        init_test_logging();
        let cryptde = cryptde();
        let this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            true,
        );
        let mut far_neighbor = make_node_record(1234, true, false);
        let mut gossip_neighbor = make_node_record(4567, true, false);
        gossip_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        gossip_neighbor
            .neighbors_mut()
            .push(far_neighbor.public_key().clone());
        far_neighbor
            .neighbors_mut()
            .push(gossip_neighbor.public_key().clone());

        let gossip = GossipBuilder::new()
            .node(&gossip_neighbor, true)
            .node(&far_neighbor, false)
            .build();
        let serialized_gossip = PlainData::new(&serde_cbor::ser::to_vec(&gossip).unwrap()[..]);
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            consuming_wallet: Some(Wallet::new("consuming")),
            remaining_route: make_meaningless_route(),
            payload: serialized_gossip,
        };
        let hopper = Recorder::new();
        let hopper_recording = hopper.get_recording();
        let hopper_awaiter = hopper.get_awaiter();
        let this_node_inside = this_node.clone();
        thread::spawn(move || {
            let system = System::new("");
            let mut subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![],
                    is_bootstrap_node: this_node_inside.is_bootstrap_node(),
                    local_ip_addr: this_node_inside.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: this_node_inside.node_addr_opt().unwrap().ports(),
                    earning_wallet: this_node_inside.earning_wallet(),
                    consuming_wallet: this_node_inside.consuming_wallet(),
                },
            );

            let mut gossip_acceptor = GossipAcceptorReal::new();
            gossip_acceptor.tcp_stream_factory = Box::new(
                TcpStreamWrapperFactoryMock::new()
                    .tcp_stream_wrapper(TcpStreamWrapperMock::new().connect_result(Ok(()))),
            );
            subject.gossip_acceptor = Box::new(gossip_acceptor);

            let addr: Addr<Syn, Neighborhood> = subject.start();
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub: Recipient<Syn, ExpiredCoresPackage> = addr.recipient::<ExpiredCoresPackage>();
            sub.try_send(cores_package).unwrap();

            system.run();
        });
        TestLogHandler::new()
            .await_log_containing(&format!("Finished processing Gossip about 2 Nodes"), 5000);
        hopper_awaiter.await_message_count(1);
        let locked_recording = hopper_recording.lock().unwrap();
        assert_eq!(1, locked_recording.len());
        let package = locked_recording.get_record(0);
        assert_eq!(&find_package_target(package), gossip_neighbor.public_key());
    }

    #[test]
    fn when_receiving_gossip_with_no_neighbors_it_gossips_only_to_source_node_to_prevent_too_many_connections(
    ) {
        // see SC-648 for why
        init_test_logging();
        let cryptde = cryptde();
        let bootstrap_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.7").unwrap(),
                &vec![1234],
            )),
            true,
        );
        let mut other_neighbor = make_node_record(1234, true, false);
        let neighborless_node = make_node_record(4567, true, false);
        other_neighbor
            .neighbors_mut()
            .push(bootstrap_node.public_key().clone());

        let gossip = GossipBuilder::new().node(&neighborless_node, true).build();
        let serialized_gossip = PlainData::new(&serde_cbor::ser::to_vec(&gossip).unwrap()[..]);
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor_ip: neighborless_node.node_addr_opt().unwrap().ip_addr(),
            consuming_wallet: Some(Wallet::new("consuming")),
            remaining_route: make_meaningless_route(),
            payload: serialized_gossip,
        };
        let hopper = Recorder::new();
        let hopper_recording = hopper.get_recording();
        let hopper_awaiter = hopper.get_awaiter();
        let bootstrap_node_inside = bootstrap_node.clone();
        let other_neighbor_inside = other_neighbor.clone();
        thread::spawn(move || {
            let system = System::new("receiving_gossip_with_no_neighbors");
            let mut subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![],
                    is_bootstrap_node: bootstrap_node_inside.is_bootstrap_node(),
                    local_ip_addr: bootstrap_node_inside.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: bootstrap_node_inside.node_addr_opt().unwrap().ports(),
                    earning_wallet: bootstrap_node_inside.earning_wallet(),
                    consuming_wallet: bootstrap_node_inside.consuming_wallet(),
                },
            );

            let mut gossip_acceptor = GossipAcceptorReal::new();
            gossip_acceptor.tcp_stream_factory = Box::new(
                TcpStreamWrapperFactoryMock::new()
                    .tcp_stream_wrapper(TcpStreamWrapperMock::new().connect_result(Ok(()))),
            );
            subject.gossip_acceptor = Box::new(gossip_acceptor);

            subject
                .neighborhood_database
                .add_node(&other_neighbor_inside)
                .expect("should be able to add a node");
            subject
                .neighborhood_database
                .add_neighbor(
                    bootstrap_node.public_key(),
                    other_neighbor_inside.public_key(),
                )
                .expect("should be able to add a neighbor");
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub: Recipient<Syn, ExpiredCoresPackage> = addr.recipient::<ExpiredCoresPackage>();
            sub.try_send(cores_package).unwrap();

            system.run();
        });
        let tlh = TestLogHandler::new();
        tlh.await_log_containing(&format!("Finished processing Gossip about 1 Nodes"), 5000);
        tlh.await_log_containing(
            &format!(
                "Relaying Gossip about 3 nodes to {:?}",
                neighborless_node.public_key()
            ),
            5000,
        );
        hopper_awaiter.await_message_count(1);
        let locked_recording = hopper_recording.lock().unwrap();
        assert_eq!(1, locked_recording.len());
        let package = locked_recording.get_record(0);
        assert_eq!(
            &find_package_target(package),
            neighborless_node.public_key()
        );
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
            true,
        );
        let mut far_neighbor = make_node_record(1234, true, false);
        let mut gossip_neighbor = make_node_record(4567, true, false);
        gossip_neighbor
            .neighbors_mut()
            .push(this_node.public_key().clone());
        gossip_neighbor
            .neighbors_mut()
            .push(far_neighbor.public_key().clone());
        far_neighbor
            .neighbors_mut()
            .push(gossip_neighbor.public_key().clone());

        let gossip = GossipBuilder::new()
            .node(&gossip_neighbor, true)
            .node(&this_node, true)
            .node(&far_neighbor, false)
            .build();
        let serialized_gossip = PlainData::new(&serde_cbor::ser::to_vec(&gossip).unwrap()[..]);
        let cores_package = ExpiredCoresPackage {
            immediate_neighbor_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            consuming_wallet: Some(Wallet::new("consuming")),
            remaining_route: make_meaningless_route(),
            payload: serialized_gossip,
        };
        let hopper = Recorder::new();
        let this_node_inside = this_node.clone();
        thread::spawn(move || {
            let system = System::new("");
            let mut subject = Neighborhood::new(
                cryptde,
                NeighborhoodConfig {
                    neighbor_configs: vec![],
                    is_bootstrap_node: this_node_inside.is_bootstrap_node(),
                    local_ip_addr: this_node_inside.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: this_node_inside.node_addr_opt().unwrap().ports(),
                    earning_wallet: this_node_inside.earning_wallet(),
                    consuming_wallet: this_node_inside.consuming_wallet(),
                },
            );

            let mut gossip_acceptor = GossipAcceptorReal::new();
            gossip_acceptor.tcp_stream_factory = Box::new(
                TcpStreamWrapperFactoryMock::new()
                    .tcp_stream_wrapper(TcpStreamWrapperMock::new().connect_result(Ok(()))),
            );
            subject.gossip_acceptor = Box::new(gossip_acceptor);

            let addr: Addr<Syn, Neighborhood> = subject.start();
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub: Recipient<Syn, ExpiredCoresPackage> = addr.recipient::<ExpiredCoresPackage>();
            sub.try_send(cores_package).unwrap();

            system.run();
        });
        TestLogHandler::new()
            .await_log_containing(&format!("Finished processing Gossip about 3 Nodes"), 5000);

        TestLogHandler::new().exists_log_containing("Received Gossip: digraph db { ");
        TestLogHandler::new().exists_log_containing("\"AQIDBA\" [label=\"AQIDBA\"];");
        TestLogHandler::new().exists_log_containing("\"9e7p7un06eHs6frl5A\" [label=\"9e7p7un06eHs6frl5A\\n5.4.3.2:1234\\nbootstrap\"] [shape=box];");
        TestLogHandler::new()
            .exists_log_containing("\"BAUGBw\" [label=\"BAUGBw\\n4.5.6.7:4567\"];");
        TestLogHandler::new().exists_log_containing("\"AQIDBA\" -> \"BAUGBw\";");
        TestLogHandler::new().exists_log_containing("\"BAUGBw\" -> \"AQIDBA\";");
        TestLogHandler::new()
            .exists_log_containing("\"BAUGBw\" -> \"9e7p7un06eHs6frl5A\" [style=dashed];");
    }

    #[test]
    fn increments_root_version_number_after_removing_a_neighbor() {
        let hopper = Recorder::new();
        let hopper_awaiter = hopper.get_awaiter();
        let hopper_recording = hopper.get_recording();
        let cryptde = cryptde();
        let this_node = NodeRecord::new_for_tests(
            &cryptde.public_key(),
            Some(&NodeAddr::new(
                &IpAddr::from_str("5.4.3.2").unwrap(),
                &vec![1234],
            )),
            true,
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
                    is_bootstrap_node: this_node_inside.is_bootstrap_node(),
                    local_ip_addr: this_node_inside.node_addr_opt().unwrap().ip_addr(),
                    clandestine_port_list: this_node_inside.node_addr_opt().unwrap().ports(),
                    earning_wallet: this_node_inside.earning_wallet(),
                    consuming_wallet: this_node_inside.consuming_wallet(),
                },
            );

            subject
                .neighborhood_database
                .add_node(&removed_neighbor_inside)
                .unwrap();
            subject
                .neighborhood_database
                .add_node(&other_neighbor_inside)
                .unwrap();
            subject
                .neighborhood_database
                .add_neighbor(&cryptde.public_key(), removed_neighbor_inside.public_key())
                .unwrap();
            subject
                .neighborhood_database
                .add_neighbor(&cryptde.public_key(), other_neighbor_inside.public_key())
                .unwrap();

            let addr: Addr<Syn, Neighborhood> = subject.start();
            let peer_actors =
                make_peer_actors_from(None, None, Some(hopper), None, None, None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap();

            let sub: Recipient<Syn, RemoveNeighborMessage> =
                addr.recipient::<RemoveNeighborMessage>();
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
        let decrypted_payload = other_neighbor_cryptde.decode(&package.payload).unwrap();
        let gossip: Gossip = serde_cbor::de::from_slice(decrypted_payload.as_slice()).unwrap();
        let the_node_record = gossip
            .node_records
            .iter()
            .find(|&x| x.inner.public_key == cryptde.public_key())
            .expect("should have the node record");
        assert_eq!(the_node_record.inner.version, 1);
    }
}
