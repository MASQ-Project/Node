// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Syn;
use sub_lib::dispatcher::Component;
use sub_lib::node_addr::NodeAddr;
use sub_lib::route::Route;
use sub_lib::cryptde::Key;
use sub_lib::neighborhood::NeighborhoodSubs;
use sub_lib::peer_actors::BindMessage;
use sub_lib::cryptde::CryptDE;
use sub_lib::neighborhood::BootstrapNeighborhoodNowMessage;
use sub_lib::neighborhood::RouteQueryMessage;
use sub_lib::neighborhood::NodeQueryMessage;
use sub_lib::neighborhood::NodeDescriptor;
use actix::MessageResult;
use sub_lib::route::RouteSegment;
use sub_lib::hopper::IncipientCoresPackage;
use actix::Recipient;
use neighborhood_database::NeighborhoodDatabase;
use gossip_acceptor::GossipAcceptor;
use sub_lib::neighborhood::NeighborhoodConfig;
use neighborhood_database::NodeRecord;
use gossip::Gossip;
use gossip_producer::GossipProducerReal;
use gossip_producer::GossipProducer;
use sub_lib::logger::Logger;
use gossip_acceptor::GossipAcceptorReal;
use sub_lib::neighborhood::RouteType;
use sub_lib::neighborhood::TargetType;
use sub_lib::neighborhood::sentinel_ip_addr;
use sub_lib::neighborhood::DispatcherNodeQueryMessage;
use sub_lib::neighborhood::RemoveNeighborMessage;
use sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
use sub_lib::utils::plus;
use sub_lib::neighborhood::RouteQueryResponse;
use sub_lib::utils::NODE_MAILBOX_CAPACITY;
use sub_lib::hopper::ExpiredCoresPackagePackage;

pub struct Neighborhood {
    cryptde: &'static CryptDE,
    hopper: Option<Recipient<Syn, IncipientCoresPackage>>,
    gossip_acceptor: Box<GossipAcceptor>,
    gossip_producer: Box<GossipProducer>,
    neighborhood_database: NeighborhoodDatabase,
    logger: Logger,
}

impl Actor for Neighborhood {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.hopper = Some (msg.peer_actors.hopper.from_hopper_client);
        ()
    }
}

impl Handler<BootstrapNeighborhoodNowMessage> for Neighborhood {
    type Result = ();

    fn handle (&mut self, _msg: BootstrapNeighborhoodNowMessage, _ctx: &mut Self::Context) -> Self::Result {
        let (bootstrap_node_keys, keys_to_report) = self.neighborhood_database.keys ().into_iter ()
            .fold ((vec! (), vec! ()), |so_far, key| {
                let (bootstrap_node_keys, keys_to_report) = so_far;
                let node = self.neighborhood_database.node_by_key (key).expect ("Node magically disappeared");
                if node.is_bootstrap_node () && (node.public_key () != self.neighborhood_database.root ().public_key ()) {
                    (plus (bootstrap_node_keys, key), keys_to_report)
                }
                else {
                    (bootstrap_node_keys, plus (keys_to_report, key))
                }
            });

        if bootstrap_node_keys.is_empty () {
            self.logger.info (format! ("No bootstrap Nodes to report to; continuing"));
            return ()
        }
        if keys_to_report.is_empty () {
            self.logger.info (format! ("Nothing to report to bootstrap Node(s)"));
            return ()
        }
        bootstrap_node_keys.into_iter ()
            .for_each (|bootstrap_node_key| {
                let gossip = self.gossip_producer.produce(&self.neighborhood_database, &bootstrap_node_key);
                let route = self.create_single_hop_route(&bootstrap_node_key);
                let package = IncipientCoresPackage::new(route, gossip.clone (), &bootstrap_node_key);
                self.logger.info (format! ("Sending initial Gossip about {} nodes to bootstrap Node at {}:{}",
                    gossip.node_records.len (), bootstrap_node_key,
                    self.neighborhood_database.node_by_key (&bootstrap_node_key).expect ("Node magically disappeared").node_addr_opt().as_ref ().expect ("internal error: must know NodeAddr of bootstrap Node")));
                self.hopper.as_ref().expect("unbound hopper").try_send(package).expect("hopper is dead");
            });
        ()
    }
}

impl Handler<NodeQueryMessage> for Neighborhood {
    type Result = MessageResult<NodeQueryMessage>;

    fn handle(&mut self, msg: NodeQueryMessage, _ctx: &mut Self::Context) -> <Self as Handler<NodeQueryMessage>>::Result {
        let node_record_ref_opt = match msg {
            NodeQueryMessage::IpAddress(ip_addr) => self.neighborhood_database.node_by_ip(&ip_addr),
            NodeQueryMessage::PublicKey(key) => self.neighborhood_database.node_by_key(&key)
        };

        MessageResult(match node_record_ref_opt {
            Some(node_record_ref) => {
                Some(NodeDescriptor::new(node_record_ref.public_key().clone(), match node_record_ref.node_addr_opt() {
                    Some(node_addr_ref) => Some(node_addr_ref.clone()),
                    None => None
                }))
            },
            None => None
        })
    }
}

impl Handler<DispatcherNodeQueryMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: DispatcherNodeQueryMessage, _ctx: &mut Self::Context) -> <Self as Handler<DispatcherNodeQueryMessage>>::Result {
        let node_record_ref_opt = match msg.query {
            NodeQueryMessage::IpAddress(ip_addr) => self.neighborhood_database.node_by_ip(&ip_addr),
            NodeQueryMessage::PublicKey(key) => self.neighborhood_database.node_by_key(&key)
        };

        let node_descriptor = match node_record_ref_opt {
            Some(node_record_ref) => {
                Some(NodeDescriptor::new(node_record_ref.public_key().clone(), match node_record_ref.node_addr_opt() {
                    Some(node_addr_ref) => Some(node_addr_ref.clone()),
                    None => None
                }))
            },
            None => None
        };

        let response = DispatcherNodeQueryResponse {
            result: node_descriptor,
            context: msg.context,
        };

        msg.recipient.try_send(response).expect("Dispatcher's StreamHandlerPool is dead");
        ()
    }
}

impl Handler<RouteQueryMessage> for Neighborhood {
    type Result = MessageResult<RouteQueryMessage>;

    fn handle(&mut self, msg: RouteQueryMessage, _ctx: &mut Self::Context) -> <Self as Handler<RouteQueryMessage>>::Result {
        let msg_str = format! ("{:?}", msg);
        let result = if msg.minimum_hop_count == 0 {
            Some (self.zero_hop_route_response())
        }
        else {
            match msg.route_type {
                RouteType::OneWay => self.make_one_way_route(msg),
                RouteType::RoundTrip => self.make_round_trip_route(msg)
            }
        };
        self.logger.trace (format! ("Processed {} into {:?}", msg_str, result));
        MessageResult (result)
    }
}

impl Handler<ExpiredCoresPackagePackage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackagePackage, _ctx: &mut Self::Context) -> Self::Result {
        let incoming_gossip: Gossip = match msg.expired_cores_package.payload() {
            Ok (p) => p,
            Err (_) => {self.logger.error (format! ("Unintelligible Gossip message received: ignoring")); return ();},
        };
        let num_nodes = incoming_gossip.node_records.len();
        self.logger.info (format! ("Processing Gossip about {} Nodes", num_nodes));

        let db_changed = self.gossip_acceptor.handle (&mut self.neighborhood_database, incoming_gossip);
        if db_changed {
            self.neighborhood_database.root().neighbors().into_iter().for_each(|key_ref| {
                    let gossip = self.gossip_producer.produce(&self.neighborhood_database, key_ref);
                    let gossip_len = gossip.node_records.len ();
                    let route = self.create_single_hop_route(key_ref);
                    let package = IncipientCoresPackage::new(route, gossip, key_ref);
                    self.logger.info (format! ("Relaying Gossip about {} nodes to {}", gossip_len, key_ref));
                    self.hopper.as_ref().expect("unbound hopper").try_send(package).expect("hopper is dead");
                });
        }
        self.logger.info (format! ("Finished processing Gossip about {} Nodes", num_nodes));
        ()
    }
}


impl Handler<RemoveNeighborMessage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: RemoveNeighborMessage, _ctx: &mut Self::Context) -> Self::Result {
        let public_key = &msg.public_key;
        match self.neighborhood_database.remove_neighbor (public_key) {
            Err (s) => self.logger.error (s),
            Ok (_) => self.logger.info(format!("removed neighbor by public key: {}", public_key)),
        }
        ()
    }
}

impl Neighborhood {
    pub fn new(cryptde: &'static CryptDE, config: NeighborhoodConfig) -> Self {
        if config.local_ip_addr == sentinel_ip_addr () {
            if !config.neighbor_configs.is_empty () {
                panic! ("A SubstratumNode without an --ip setting is not decentralized and cannot have any --neighbor settings")
            }
            if !config.bootstrap_configs.is_empty () {
                panic! ("A SubstratumNode without an --ip setting is not decentralized and cannot have any --bootstrap_from settings")
            }
            if !config.clandestine_port_list.is_empty () {
                panic! ("A SubstratumNode without an --ip setting is not decentralized and cannot have any --port_count setting other than 0")
            }
            if config.is_bootstrap_node {
                panic! ("A SubstratumNode without an --ip setting is not decentralized and cannot be --node_type bootstrap")
            }
        }
        else if (config.neighbor_configs.is_empty () && config.bootstrap_configs.is_empty () && !config.is_bootstrap_node) || config.clandestine_port_list.is_empty () {
            panic! ("An --ip setting indicates that you want to decentralize, but you also need at least one --neighbor or --bootstrap_from setting or --node_type bootstrap for that, and a --port_count greater than 0")
        }
        let gossip_acceptor : Box<GossipAcceptor> = Box::new (GossipAcceptorReal::new());
        let gossip_producer = Box::new (GossipProducerReal::new ());
        let local_node_addr = NodeAddr::new (&config.local_ip_addr, &config.clandestine_port_list);
        let mut neighborhood_database = NeighborhoodDatabase::new (&cryptde.public_key(), &local_node_addr, config.is_bootstrap_node, cryptde);

        let add_node = |neighborhood_database: &mut NeighborhoodDatabase, neighbor: &(Key, NodeAddr), is_bootstrap_node: bool| {
            let (key, node_addr) = neighbor;
            let root_key_ref = &neighborhood_database.root().public_key().clone();
            neighborhood_database.add_node(&NodeRecord::new(&key, Some(&node_addr), is_bootstrap_node, None)).expect(&format! ("Database already contains node {:?}", key));
            neighborhood_database.add_neighbor(root_key_ref, &key).expect("internal error");
        };

        // TODO: Take this out when Bootstrap databases are no longer linear
        if !config.neighbor_configs.is_empty() && !config.bootstrap_configs.is_empty() {
            panic! ("While bootstrap Node databases are linear, specify either --neighbor or --bootstrap_from (or neither), but not both");
        }

        config.neighbor_configs.iter().for_each(|neighbor| add_node(&mut neighborhood_database,neighbor, false));
        config.bootstrap_configs.iter().for_each(|neighbor| add_node(&mut neighborhood_database, neighbor, true));

        Neighborhood {
            cryptde,
            hopper: None,
            gossip_acceptor,
            gossip_producer,
            neighborhood_database,
            logger: Logger::new ("Neighborhood"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Syn, Neighborhood>) -> NeighborhoodSubs {
        NeighborhoodSubs {
            bind: addr.clone ().recipient::<BindMessage>(),
            bootstrap: addr.clone ().recipient::<BootstrapNeighborhoodNowMessage>(),
            node_query: addr.clone ().recipient::<NodeQueryMessage>(),
            route_query: addr.clone ().recipient::<RouteQueryMessage>(),
            from_hopper: addr.clone ().recipient::<ExpiredCoresPackagePackage>(),
            dispatcher_node_query: addr.clone().recipient::<DispatcherNodeQueryMessage>(),
            remove_neighbor: addr.clone().recipient::<RemoveNeighborMessage>(),
        }
    }

    fn create_single_hop_route(&self, destination: &Key) -> Route {
        // TODO While the database is forced linear, the route sought here doesn't exist in the database and has to be hacked up here.
        Route::new(vec! (RouteSegment::new(vec! (&self.cryptde.public_key(), destination), Component::Neighborhood)), self.cryptde).expect("route creation error")
    }

    fn zero_hop_route_response(&self) -> RouteQueryResponse {
        let route = Route::new(vec! (
            RouteSegment::new(vec! (&self.cryptde.public_key(), &self.cryptde.public_key ()), Component::ProxyClient),
            RouteSegment::new(vec! (&self.cryptde.public_key(), &self.cryptde.public_key()), Component::ProxyServer)
        ), self.cryptde).expect("Couldn't create route");
        RouteQueryResponse {route, segment_endpoints: vec! (self.cryptde.public_key (), self.cryptde.public_key ())}
    }

    fn make_one_way_route (&self, msg: RouteQueryMessage) -> Option<RouteQueryResponse> {
        match self.make_route_segment(&self.cryptde.public_key(), msg.target_key_opt.as_ref(), msg.target_type, msg.minimum_hop_count, msg.target_component) {
            Some(segment) => {
                let segment_endpoint = segment.keys.last ().expect ("empty segment").clone ();
                Some (RouteQueryResponse {
                    route: Route::new(vec! (segment), self.cryptde).expect("bad route"),
                    segment_endpoints: vec! (segment_endpoint),
                })
            },
            None => None
        }
    }

    fn make_round_trip_route (&self, msg: RouteQueryMessage) -> Option<RouteQueryResponse> {
        let local_target_type = if self.neighborhood_database.root().is_bootstrap_node() { TargetType::Bootstrap } else { TargetType::Standard };
        let mut segment_endpoints: Vec<Key> = vec! ();
        if let Some(over) = self.make_route_segment(
            &self.cryptde.public_key(),
            msg.target_key_opt.as_ref(),
            msg.target_type,
            msg.minimum_hop_count,
            msg.target_component
        ) {
            segment_endpoints.push (over.keys.last ().expect ("empty segment").clone ());
            self.logger.debug (format! ("Route over: {:?}", over));
            if let Some (back) = self.make_route_segment(
                over.keys.last().expect("Empty segment"),
                Some(&self.cryptde.public_key()),
                local_target_type,
                msg.minimum_hop_count,
                msg.return_component_opt.expect("No return component")
            ) {
                segment_endpoints.push (back.keys.last ().expect ("empty segment").clone ());
                self.logger.debug (format! ("Route back: {:?}", back));
                return Some(RouteQueryResponse {
                    route: Route::new(vec!(over, back), self.cryptde).expect("Bad route"),
                    segment_endpoints,
                })
            }
        }
        None
    }

    fn make_route_segment(&self, origin: &Key, target: Option<&Key>, target_type: TargetType, minimum_hop_count: usize, target_component: Component) -> Option<RouteSegment> {
        let mut node_seqs = self.complete_routes (vec! (origin), target, target_type,minimum_hop_count);
        if node_seqs.is_empty () { return None; }
        let chosen_node_seq = node_seqs.remove(0);
        Some (RouteSegment::new(chosen_node_seq, target_component))
    }

    fn route_length_qualifies (&self, hops_remaining: usize) -> bool {
        hops_remaining == 0
    }

    fn last_key_qualifies (&self, last_node_ref: &NodeRecord, target_key_ref_opt: Option<&Key>) -> bool {
        match target_key_ref_opt {
            Some(target_key_ref) => last_node_ref.public_key() == target_key_ref,
            None => true
        }
    }

    fn last_type_qualifies (&self, last_node_ref: &NodeRecord, target_type: TargetType) -> bool {
        (target_type == TargetType::Bootstrap) == last_node_ref.is_bootstrap_node ()
    }

    // Main recursive routing engine. Supply origin key as single-element vector in prefix,
    // target key, if any, in target, and minimum hop count in hops_remaining. Return value is
    // a list of all the node sequences that will either go from the origin to the target in
    // hops_remaining or more hops with no cycles, or from the origin hops_remaining hops out into
    // the Substratum Network. No round trips; if you want a round trip, call this method twice.
    // If the return value is empty, no qualifying route was found.
    fn complete_routes<'a> (&'a self, prefix: Vec<&'a Key>, target: Option<&'a Key>, target_type: TargetType, hops_remaining: usize) -> Vec<Vec<&'a Key>> {
        let last_node_ref = self.neighborhood_database.node_by_key(prefix.last ().expect ("Empty prefix")).expect ("Node magically disappeared");
        // Check to see if we're done. If we are, all three of these qualifications will pass.
        if self.route_length_qualifies (hops_remaining) &&
            self.last_key_qualifies (last_node_ref, target) &&
            self.last_type_qualifies (last_node_ref, target_type) {
            vec! (prefix)
        }
        // If we're not done, then last_node is for routing, and bootstrap Nodes don't route.
        else if last_node_ref.is_bootstrap_node () {
            vec! ()
        }
        // Go through all the neighbors and compute shorter routes through all the ones we're not already using.
        else {
            last_node_ref.neighbors ().iter ()
            .filter (|neighbor_key_ref_ref| !prefix.contains(neighbor_key_ref_ref))
            .flat_map (|neighbor_key_ref_ref| {
                let mut new_prefix = prefix.clone ();
                new_prefix.push (neighbor_key_ref_ref);
                self.complete_routes(new_prefix.clone (), target, target_type, if hops_remaining == 0 { 0 } else { hops_remaining - 1 })
            })
            .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::net::IpAddr;
    use actix::Arbiter;
    use actix::Recipient;
    use actix::System;
    use actix::msgs;
    use tokio::prelude::Future;
    use serde_cbor;
    use test_utils::test_utils::cryptde;
    use neighborhood_test_utils::make_node_record;
    use gossip::GossipBuilder;
    use std::thread;
    use test_utils::recorder::Recorder;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::test_utils::make_meaningless_route;
    use sub_lib::cryptde::PlainData;
    use sub_lib::cryptde_null::CryptDENull;
    use gossip::Gossip;
    use neighborhood_test_utils::vec_to_set;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::sync::Arc;
    use gossip_acceptor::GossipAcceptorReal;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use gossip::GossipNodeRecord;
    use sub_lib::neighborhood::sentinel_ip_addr;
    use sub_lib::stream_handler_pool::TransmitDataMsg;
    use sub_lib::dispatcher::Endpoint;
    use test_utils::recorder::Recording;
    use test_utils::recorder::make_recorder;
    use sub_lib::hopper::ExpiredCoresPackage;
    use test_utils::test_utils::assert_contains;

    #[test]
    #[should_panic (expected = "A SubstratumNode without an --ip setting is not decentralized and cannot have any --neighbor settings")]
    fn neighborhood_cannot_be_created_with_neighbors_and_default_ip () {
        let cryptde = cryptde ();
        let neighbor = make_node_record(1234, true, false);

        Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (
                (neighbor.public_key().clone(), neighbor.node_addr_opt().unwrap().clone()),
            ),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr (),
            clandestine_port_list: vec! (),
        });
    }

    #[test]
    #[should_panic (expected = "A SubstratumNode without an --ip setting is not decentralized and cannot have any --bootstrap_from settings")]
    fn neighborhood_cannot_be_created_with_bootstrap_froms_and_default_ip () {
        let cryptde = cryptde ();
        let bootstrap_from = make_node_record(1234, true, false);

        Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (
                (bootstrap_from.public_key().clone(), bootstrap_from.node_addr_opt().unwrap().clone()),
            ),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr (),
            clandestine_port_list: vec! (),
        });
    }

    #[test]
    #[should_panic (expected = "A SubstratumNode without an --ip setting is not decentralized and cannot have any --port_count setting other than 0")]
    fn neighborhood_cannot_be_created_with_clandestine_ports_and_default_ip () {
        let cryptde = cryptde ();

        Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr (),
            clandestine_port_list: vec! (1234),
        });
    }

    #[test]
    #[should_panic (expected = "A SubstratumNode without an --ip setting is not decentralized and cannot be --node_type bootstrap")]
    fn neighborhood_cannot_be_created_as_a_bootstrap_node_with_default_ip () {
        let cryptde = cryptde ();

        Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: true,
            local_ip_addr: sentinel_ip_addr (),
            clandestine_port_list: vec! (),
        });
    }

    #[test]
    #[should_panic (expected = "An --ip setting indicates that you want to decentralize, but you also need at least one --neighbor or --bootstrap_from setting or --node_type bootstrap for that, and a --port_count greater than 0")]
    fn neighborhood_cannot_be_created_with_ip_and_neighbors_but_no_clandestine_ports () {
        let cryptde = cryptde ();
        let neighbor = make_node_record(1234, true, false);

        Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (
                (neighbor.public_key().clone(), neighbor.node_addr_opt().unwrap().clone()),
            ),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("2.3.4.5").unwrap (),
            clandestine_port_list: vec! (),
        });
    }

    #[test]
    #[should_panic (expected = "An --ip setting indicates that you want to decentralize, but you also need at least one --neighbor or --bootstrap_from setting or --node_type bootstrap for that, and a --port_count greater than 0")]
    fn neighborhood_cannot_be_created_with_ip_and_bootstrap_froms_but_no_clandestine_ports () {
        let cryptde = cryptde ();
        let bootstrap_from = make_node_record(1234, true, false);

        Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (
                (bootstrap_from.public_key().clone(), bootstrap_from.node_addr_opt().unwrap().clone()),
            ),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("2.3.4.5").unwrap (),
            clandestine_port_list: vec! (),
        });
    }

    #[test]
    #[should_panic (expected = "An --ip setting indicates that you want to decentralize, but you also need at least one --neighbor or --bootstrap_from setting or --node_type bootstrap for that, and a --port_count greater than 0")]
    fn neighborhood_cannot_be_created_with_ip_and_clandestine_ports_but_no_neighbors_or_bootstrap_froms () {
        let cryptde = cryptde ();

        Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("2.3.4.5").unwrap (),
            clandestine_port_list: vec! (2345),
        });
    }

    #[test]
    fn bootstrap_node_neighborhood_creates_single_node_database () {
        let cryptde = cryptde ();
        let this_node_addr = NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (5678));

        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: true,
            local_ip_addr: this_node_addr.ip_addr (),
            clandestine_port_list: this_node_addr.ports ().clone (),
        });

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq! (root_node_record_ref.public_key (), &cryptde.public_key ());
        assert_eq! (root_node_record_ref.node_addr_opt (), Some (this_node_addr));
        assert_eq! (root_node_record_ref.is_bootstrap_node (), true);
        assert_eq! (root_node_record_ref.neighbors ().len (), 0);
    }

    #[test]
    fn bootstrap_node_with_no_bootstrap_nodes_ignores_bootstrap_neighborhood_now_message () {
        init_test_logging();
        let cryptde = cryptde ();
        let system = System::new ("bootstrap_node_ignores_bootstrap_neighborhood_now_message");
        let subject = Neighborhood::new(cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: true,
            local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
            clandestine_port_list: vec! (5678),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, BootstrapNeighborhoodNowMessage> = addr.clone ().recipient::<BootstrapNeighborhoodNowMessage> ();
        let (hopper, _, hopper_recording_arc) = make_recorder ();
        let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
        addr.try_send(BindMessage { peer_actors }).unwrap ();

        sub.try_send(BootstrapNeighborhoodNowMessage {}).unwrap ();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        let recording = hopper_recording_arc.lock ().unwrap ();
        assert_eq! (recording.len (), 0);
        TestLogHandler::new ().exists_log_containing ("INFO: Neighborhood: No bootstrap Nodes to report to; continuing");
    }

    #[test]
    fn neighborhood_adds_nodes_and_links_without_bootstraps() {
        let cryptde = cryptde ();
        let one_node = make_node_record(1234, true, false);
        let another_node = make_node_record(2345, true, false);
        let this_node_addr = NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (5678));

        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (
                (one_node.public_key().clone(), one_node.node_addr_opt().unwrap().clone()),
                (another_node.public_key().clone(), another_node.node_addr_opt().unwrap().clone())
            ),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: this_node_addr.ip_addr (),
            clandestine_port_list: this_node_addr.ports ().clone (),
        });

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(root_node_record_ref.node_addr_opt().unwrap().clone(), this_node_addr);
        assert_eq!(root_node_record_ref.is_bootstrap_node(), false);

        assert_eq!(root_node_record_ref.has_neighbor(one_node.public_key()), true);
        assert_eq!(root_node_record_ref.has_neighbor(another_node.public_key()), true);

        assert_eq!(subject.neighborhood_database.node_by_key(one_node.public_key()).unwrap().is_bootstrap_node(), false);
        assert_eq!(subject.neighborhood_database.node_by_key(another_node.public_key()).unwrap().is_bootstrap_node(), false);
    }

    #[test]
    fn neighborhood_adds_nodes_and_links_without_neighbors() {
        let cryptde = cryptde ();
        let one_bootstrap_node = make_node_record(3456, true, true);
        let another_bootstrap_node = make_node_record(4567, true, true);
        let this_node_addr = NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (5678));

        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (
                (one_bootstrap_node.public_key().clone(), one_bootstrap_node.node_addr_opt().unwrap().clone()),
                (another_bootstrap_node.public_key().clone(), another_bootstrap_node.node_addr_opt().unwrap().clone())
            ),
            is_bootstrap_node: false,
            local_ip_addr: this_node_addr.ip_addr (),
            clandestine_port_list: this_node_addr.ports ().clone (),
        });

        let root_node_record_ref = subject.neighborhood_database.root();

        assert_eq!(root_node_record_ref.node_addr_opt().unwrap().clone(), this_node_addr);
        assert_eq!(root_node_record_ref.is_bootstrap_node(), false);

        assert_eq! (root_node_record_ref.has_neighbor(one_bootstrap_node.public_key()), true);
        assert_eq! (root_node_record_ref.has_neighbor(another_bootstrap_node.public_key()), true);

        assert_eq!(subject.neighborhood_database.node_by_key(one_bootstrap_node.public_key()).unwrap().is_bootstrap_node(), true);
        assert_eq!(subject.neighborhood_database.node_by_key(another_bootstrap_node.public_key()).unwrap().is_bootstrap_node(), true);
    }

    #[test]
    fn node_query_responds_with_none_when_initially_configured_with_no_data () {
        let cryptde = cryptde ();
        let system = System::new ("responds_with_none_when_initially_configured_with_no_data");
        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr (),
            clandestine_port_list: vec! (),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, NodeQueryMessage> = addr.recipient::<NodeQueryMessage> ();

        let future = sub.send(NodeQueryMessage::PublicKey (Key::new (&b"booga"[..])));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        let result = future.wait ().unwrap ();
        assert_eq! (result.is_none (), true);
    }

    #[test]
    fn node_query_responds_with_none_when_key_query_matches_no_configured_data () {
        let cryptde = cryptde ();
        let system = System::new ("responds_with_none_when_initially_configured_with_no_data");
        let subject = Neighborhood::new(cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (
                (Key::new (&b"booga"[..]), NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap(), &vec! (1234, 2345))),
            ),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
            clandestine_port_list: vec! (5678),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, NodeQueryMessage> = addr.recipient::<NodeQueryMessage> ();

        let future = sub.send(NodeQueryMessage::PublicKey (Key::new (&b"blah"[..])));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        let result = future.wait ().unwrap ();
        assert_eq! (result.is_none (), true);
    }

    #[test]
    fn node_query_responds_with_result_when_key_query_matches_configured_data () {
        let cryptde = cryptde ();
        let system = System::new ("responds_with_none_when_initially_configured_with_no_data");
        let one_neighbor = make_node_record(2345, true, false);
        let another_neighbor = make_node_record(3456, true, false);
        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (
                node_record_to_pair(&one_neighbor),
                node_record_to_pair(&another_neighbor),
            ),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
            clandestine_port_list: vec! (5678),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, NodeQueryMessage> = addr.recipient::<NodeQueryMessage> ();

        let future = sub.send(NodeQueryMessage::PublicKey (another_neighbor.public_key ().clone ()));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        let result = future.wait ().unwrap ();
        assert_eq! (result.unwrap (), NodeDescriptor::new (another_neighbor.public_key().clone(), Some(another_neighbor.node_addr_opt().unwrap().clone())));
    }

    #[test]
    fn node_query_responds_with_none_when_ip_address_query_matches_no_configured_data () {
        let cryptde = cryptde ();
        let system = System::new ("responds_with_none_when_initially_configured_with_no_data");
        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (
                (Key::new (&b"booga"[..]), NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap(), &vec! (1234, 2345))),
            ),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
            clandestine_port_list: vec! (5678),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, NodeQueryMessage> = addr.recipient::<NodeQueryMessage> ();

        let future = sub.send(NodeQueryMessage::IpAddress (IpAddr::from_str("2.3.4.5").unwrap()));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        let result = future.wait ().unwrap ();
        assert_eq! (result.is_none (), true);
    }

    #[test]
    fn node_query_responds_with_result_when_ip_address_query_matches_configured_data () {
        let cryptde = cryptde ();
        let system = System::new ("responds_with_none_when_initially_configured_with_no_data");
        let node_record = make_node_record(1234, true, false);
        let another_node_record = make_node_record(2345, true, false);
        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (
                (node_record.public_key().clone (), node_record.node_addr_opt().unwrap().clone()),
                (another_node_record.public_key().clone (), another_node_record.node_addr_opt ().unwrap ().clone ()),
            ),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: node_record.node_addr_opt().as_ref ().unwrap ().ip_addr (),
            clandestine_port_list: node_record.node_addr_opt ().as_ref ().unwrap ().ports ().clone (),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, NodeQueryMessage> = addr.recipient::<NodeQueryMessage> ();

        let future = sub.send(NodeQueryMessage::IpAddress (IpAddr::from_str("1.2.3.4").unwrap()));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        let result = future.wait ().unwrap ();
        assert_eq! (result.unwrap (), NodeDescriptor::new (node_record.public_key().clone(), Some(node_record.node_addr_opt().unwrap().clone())));
    }

    #[test]
    fn route_query_responds_with_none_when_asked_for_route_with_too_many_hops () {
        let cryptde = cryptde ();
        let system = System::new ("responds_with_none_when_asked_for_route_with_empty_database");
        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr (),
            clandestine_port_list: vec! (),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage> ();

        let future = sub.send (RouteQueryMessage::data_indefinite_route_request (5));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        let result = future.wait ().unwrap ();
        assert_eq! (result, None);
    }

    #[test]
    fn route_query_responds_with_standard_zero_hop_route_when_requested () {
        let cryptde = cryptde ();
        let system = System::new ("responds_with_standard_zero_hop_route_when_requested");
        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr (),
            clandestine_port_list: vec! (),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage> ();

        let future = sub.send (RouteQueryMessage::data_indefinite_route_request (0));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        let result = future.wait ().unwrap ().unwrap ();
        let expected_response = RouteQueryResponse {
            route: Route::new(vec!(
                RouteSegment::new(vec!(&cryptde.public_key(), &cryptde.public_key()), Component::ProxyClient),
                RouteSegment::new(vec!(&cryptde.public_key(), &cryptde.public_key()), Component::ProxyServer)
            ), cryptde).unwrap(),
            segment_endpoints: vec!(cryptde.public_key (), cryptde.public_key ()),
        };
        assert_eq! (result, expected_response);
    }

    /*
            Database, where B is bootstrap and the rest are standard:

                 +---+-B-+---+
                 |   |   |   |
                 P---Q---R---S

            Tests will be written from the viewpoint of P.
    */

    #[test]
    fn route_query_messages () {
        let cryptde = cryptde();
        let system = System::new("two_hops_from_p");
        let mut subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr (),
            clandestine_port_list: vec! (),
        });
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
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| {dual_edge_func (db, a, b)};
            dual_edge (b, p);
            dual_edge (b, q);
            dual_edge (b, r);
            dual_edge (b, s);
            dual_edge (p, q);
            dual_edge (q, r);
            dual_edge (r, s);
        }

        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage> ();

        let gossip_route = sub.send (RouteQueryMessage::gossip_route_request(b.public_key (), 4));
        let data_route = sub.send (RouteQueryMessage::data_indefinite_route_request (2));

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        let segment = |nodes: Vec<&NodeRecord>, component: Component| {
            RouteSegment::new(nodes.into_iter ().map (|n| n.public_key ()).collect (), component)
        };

        let result = gossip_route.wait ().unwrap ().unwrap ();
        let expected_response = RouteQueryResponse {
            route: Route::new(vec!(
                segment(vec!(p, q, r, s, b), Component::Neighborhood)
            ), cryptde).unwrap(),
            segment_endpoints: vec!(b.public_key ().clone ())
        };
        assert_eq! (result, expected_response);

        let result = data_route.wait ().unwrap ().unwrap ();
        let expected_response = RouteQueryResponse {
            route: Route::new(vec!(
                segment(vec!(p, q, r), Component::ProxyClient),
                segment(vec!(r, q, p), Component::ProxyServer),
            ), cryptde).unwrap(),
            segment_endpoints: vec!(r.public_key ().clone (), p.public_key ().clone ())
        };
        assert_eq! (result, expected_response);
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
    fn complete_routes_exercise () {
        let mut subject = Neighborhood::new (cryptde (), NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr (),
            clandestine_port_list: vec! (),
        });
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
            let mut dual_edge = |a: &NodeRecord, b: &NodeRecord| {dual_edge_func (db, a, b)};
            dual_edge (b, p);
            dual_edge (b, r);
            dual_edge (q, p);
            dual_edge (p, r);
            dual_edge (p, s);
            dual_edge (t, s);
            dual_edge (s, r);
        }

        let contains = |routes: &Vec<Vec<&Key>>, expected_nodes: Vec<&NodeRecord>| {
            let expected_keys: Vec<&Key> = expected_nodes.into_iter ().map (|n| n.public_key ()).collect ();
            assert_contains (&routes, &expected_keys);
        };

        // At least two hops from P to anywhere standard
        let routes = subject.complete_routes (vec! (p.public_key ()), None, TargetType::Standard, 2);

        contains (&routes, vec! (p, s, t));
        contains (&routes, vec! (p, r, s));
        contains (&routes, vec! (p, s, r));
        assert_eq! (routes.len(), 3);

        // At least two hops from P to T
        let routes = subject.complete_routes(vec! (p.public_key()), Some(t.public_key()), TargetType::Standard, 2);

        contains (&routes, vec! (p, s, t));
        contains (&routes, vec! (p, r, s, t));
        assert_eq! (routes.len(), 2);

        // At least two hops from P to B (bootstrap)
        let routes = subject.complete_routes(vec! (p.public_key()), Some(b.public_key()), TargetType::Bootstrap, 2);

        contains (&routes, vec! (p, r, b));
        contains (&routes, vec! (p, s, r, b));
        assert_eq! (routes.len(), 2);

        // At least two hops from P to anywhere bootstrap
        let routes = subject.complete_routes (vec! (p.public_key ()), None, TargetType::Bootstrap, 2);

        contains (&routes, vec! (p, r, b));
        contains (&routes, vec! (p, s, r, b));
        assert_eq! (routes.len(), 2);

        // At least two hops from P to S - one choice
        let routes = subject.complete_routes (vec! (p.public_key()), Some(s.public_key()), TargetType::Standard,2);

        contains (&routes, vec! (p, r, s));
        assert_eq! (routes.len(), 1);

        // At least two hops from P to Q - impossible
        let routes = subject.complete_routes (vec! (p.public_key()), Some(q.public_key()), TargetType::Standard, 2);

        assert_eq! (routes.len(), 0);

        // At least two hops from P to R (bootstrap) - impossible
        let routes = subject.complete_routes (vec! (p.public_key()), Some(r.public_key()), TargetType::Bootstrap, 2);

        assert_eq! (routes.len(), 0);
    }

    #[test]
    fn bad_cores_package_is_logged_and_ignored () {
        let cryptde = cryptde ();
        init_test_logging ();
        let cores_package = ExpiredCoresPackagePackage { expired_cores_package: ExpiredCoresPackage::new (make_meaningless_route (), PlainData::new (&b"booga"[..])), sender_ip: IpAddr::from_str("1.2.3.4").unwrap() };
        let system = System::new ("");
        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr(),
            clandestine_port_list: vec! (),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, ExpiredCoresPackagePackage> = addr.recipient::<ExpiredCoresPackagePackage> ();

        sub.try_send (cores_package).unwrap ();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        TestLogHandler::new ().exists_log_containing ("ERROR: Neighborhood: Unintelligible Gossip message received: ignoring");
    }

    #[test]
    fn neighborhood_sends_gossip_when_db_changes() {
        let cryptde = cryptde ();
        let mut this_node = NodeRecord::new_for_tests (&cryptde.public_key (), Some (&NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (1234))), true);
        let mut gossip_neighbor = make_node_record (4567, true, false);
        gossip_neighbor.neighbors_mut ().push (this_node.public_key ().clone ());
        let gossip = GossipBuilder::new ().node (&gossip_neighbor, true).build ();
        let serialized_gossip = PlainData::new (&serde_cbor::ser::to_vec (&gossip).unwrap ()[..]);
        let cores_package = ExpiredCoresPackagePackage { expired_cores_package: ExpiredCoresPackage::new (make_meaningless_route (), serialized_gossip), sender_ip: IpAddr::from_str("1.2.3.4").unwrap() };
        let hopper = Recorder::new ();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording = hopper.get_recording ();
        let this_node_inside = this_node.clone ();
        thread::spawn (move || {
            let system = System::new ("");
            let mut subject = Neighborhood::new (cryptde, NeighborhoodConfig {
                neighbor_configs: vec! (),
                bootstrap_configs: vec! (),
                is_bootstrap_node: this_node_inside.is_bootstrap_node(),
                local_ip_addr: this_node_inside.node_addr_opt().unwrap ().ip_addr(),
                clandestine_port_list: this_node_inside.node_addr_opt().unwrap ().ports(),
            });
            let addr: Addr<Syn, Neighborhood> = subject.start ();
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap ();

            let sub: Recipient<Syn, ExpiredCoresPackagePackage> = addr.recipient::<ExpiredCoresPackagePackage> ();
            sub.try_send (cores_package).unwrap ();

            system.run ();
        });
        hopper_awaiter.await_message_count (1);
        let locked_recording = hopper_recording.lock ().unwrap ();
        let package = locked_recording.get_record (0);
        // Now make this_node look the way subject's initial NodeRecord will have looked after receiving the Gossip, so that
        // it appears correct for check_outgoing_package.
        this_node.neighbors_mut ().push (gossip_neighbor.public_key ().clone ());

        if &find_package_target (package) == gossip_neighbor.public_key () {
            check_outgoing_package(package, &this_node, &gossip_neighbor);
        }
        else {
            assert_eq!(true, false, "Got unexpected Gossip message: {:?}", package);
        }
    }

    #[test]
    fn standard_node_requests_bootstrap_properly () {
        let cryptde = cryptde ();
        let bootstrap_node = make_node_record (1234, true, true);
        let hopper = Recorder::new ();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording = hopper.get_recording ();
        let bootstrap_node_inside = bootstrap_node.clone ();
        thread::spawn (move || {
            let system = System::new ("standard_node_requests_bootstrap_properly");
            let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
                neighbor_configs: vec! (),
                bootstrap_configs: vec! ((bootstrap_node_inside.public_key ().clone (), bootstrap_node_inside.node_addr_opt ().unwrap ().clone ())),
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
                clandestine_port_list: vec! (1234),
            });
            let addr: Addr<Syn, Neighborhood> = subject.start ();
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap ();

            let sub: Recipient<Syn, BootstrapNeighborhoodNowMessage> = addr.recipient::<BootstrapNeighborhoodNowMessage> ();
            sub.try_send (BootstrapNeighborhoodNowMessage {}).unwrap ();

            system.run ();
        });
        hopper_awaiter.await_message_count (1);
        let locked_recording = hopper_recording.lock ().unwrap ();
        let package_ref: &IncipientCoresPackage = locked_recording.get_record (0);
        check_direct_route_to (&package_ref.route, bootstrap_node.public_key ());
        assert_eq!(&package_ref.payload_destination_key, bootstrap_node.public_key());
        let gossip: Gossip = serde_cbor::de::from_slice(&package_ref.payload.data[..]).unwrap();
        let mut this_node = NodeRecord::new_for_tests (&cryptde.public_key (),
            Some (&NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (1234))), false);
        this_node.neighbors_mut().push (bootstrap_node.public_key().clone ());
        assert_contains (&gossip.node_records, &GossipNodeRecord::from (&this_node, true));
        assert_eq! (gossip.node_records.len (), 1);
        assert_eq! (gossip.neighbor_pairs, vec! ());
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
    fn neighborhood_removes_neighbor_when_directed_to () {
        let cryptde = cryptde();
        let system = System::new("neighborhood_removes_neighbor_when_directed_to");
        let mut subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr(),
            clandestine_port_list: vec! (),
        });
        let n = &subject.neighborhood_database.root().clone();
        let a = &make_node_record(3456, true, false);
        let b = &make_node_record(4567, false, false);
        let c = &make_node_record(5678, true, false);
        {
            let db = &mut subject.neighborhood_database;
            db.add_node(a).unwrap();
            db.add_node(b).unwrap();
            db.add_node(c).unwrap();
            let mut edge = |a: &NodeRecord, b: &NodeRecord| {single_edge_func (db, a, b)};
            edge (n, a);
            edge (n, c);
            edge (a, b);
            edge (b, a);
            edge (b, c);
            edge (c, b);
        }
        let addr: Addr<Syn, Neighborhood> = subject.start ();

        addr.try_send (RemoveNeighborMessage { public_key: a.public_key ().clone ()}).unwrap ();

        let three_hop_route_request = RouteQueryMessage {
            route_type: RouteType::OneWay,
            target_type: TargetType::Standard,
            target_key_opt: Some(c.public_key().clone()),
            target_component: Component::ProxyClient,
            minimum_hop_count: 3,
            return_component_opt: None,
        };
        let unsuccessful_three_hop_route = addr.send (three_hop_route_request);
        let public_key_query = addr.send (NodeQueryMessage::PublicKey (a.public_key ().clone ()));
        let failed_ip_address_query = addr.send (NodeQueryMessage::IpAddress (a.node_addr_opt ().unwrap ().ip_addr ()));
        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();

        system.run ();
        assert_eq! (None, unsuccessful_three_hop_route.wait ().unwrap ());
        assert_eq! (a.public_key(), &public_key_query.wait ().unwrap ().unwrap().public_key);
        assert_eq! (None, failed_ip_address_query.wait ().unwrap ());
    }

    fn node_record_to_pair (node_record_ref: &NodeRecord) -> (Key, NodeAddr) {
        (node_record_ref.public_key ().clone (), node_record_ref.node_addr_opt ().unwrap ().clone ())
    }

    fn find_package_target (package: &IncipientCoresPackage) -> Key {
        let mut route = package.route.clone ();
        let hop = route.shift (cryptde()).unwrap ();
        hop.public_key
    }

    fn check_direct_route_to (route: &Route, destination: &Key) {
        let mut route = route.clone ();
        let hop = route.shift(cryptde()).unwrap();
        assert_eq!(&hop.public_key, destination);
        assert_eq!(hop.component, Component::Hopper);
        let hop = route.shift(&CryptDENull::from(&destination)).unwrap();
        assert_eq!(hop.component, Component::Neighborhood);
    }

    // Checks that cores_package contains the following Gossip:   target <=> source
    fn check_outgoing_package(cores_package: &IncipientCoresPackage, source: &NodeRecord, target: &NodeRecord) -> NeighborhoodDatabase {
        check_direct_route_to (&cores_package.route, target.public_key ());
        assert_eq!(&cores_package.payload_destination_key, target.public_key());
        let deserialized_payload: Gossip = serde_cbor::de::from_slice(&cores_package.payload.data[..]).unwrap();
        let mut database = NeighborhoodDatabase::new(target.public_key(), &target.node_addr_opt().unwrap (),
                                                     false, &CryptDENull::from(target.public_key()));
        GossipAcceptorReal::new().handle(&mut database, deserialized_payload);
        assert_eq!(database.node_by_key(source.public_key()).unwrap(), source);
        assert_eq!(database.node_by_key(target.public_key()).unwrap(), target);

        check_is_neighbor(&database, source, target);
        check_is_neighbor(&database, target, source);

        database
    }

    fn check_is_neighbor(database: &NeighborhoodDatabase, from: &NodeRecord, to: &NodeRecord) {
        assert_eq! (database.has_neighbor (from.public_key (), to.public_key ()), true, "Node {:?} should have {:?} as its neighbor, but doesn't:\n{:?}", from.public_key (), to.public_key (), database);
    }

    fn check_is_not_neighbor(database: &NeighborhoodDatabase, from: &NodeRecord, to: &NodeRecord) {
        assert_eq! (database.has_neighbor (from.public_key (), to.public_key ()), false, "Node {:?} should not have {:?} as its neighbor, but does:\n{:?}", from.public_key (), to.public_key (), database);
    }

    fn dual_edge_func (db: &mut NeighborhoodDatabase, a: &NodeRecord, b: &NodeRecord) {
        db.add_neighbor(a.public_key(), b.public_key()).unwrap();
        db.add_neighbor(b.public_key(), a.public_key()).unwrap();
    }

    fn single_edge_func (db: &mut NeighborhoodDatabase, a: &NodeRecord, b: &NodeRecord) {
        db.add_neighbor(a.public_key(), b.public_key()).unwrap();
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_none_when_initially_configured_with_no_data () {
        let cryptde = cryptde ();
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new ("responds_with_none_when_initially_configured_with_no_data");

            let addr: Addr<Syn, Recorder> = recorder.start();
            let recipient: Recipient<Syn, DispatcherNodeQueryResponse> = addr.recipient::<DispatcherNodeQueryResponse>();

            let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
                neighbor_configs: vec! (),
                bootstrap_configs: vec! (),
                is_bootstrap_node: false,
                local_ip_addr: sentinel_ip_addr (),
                clandestine_port_list: vec! (),
            });
            let addr: Addr<Syn, Neighborhood> = subject.start ();
            let sub: Recipient<Syn, DispatcherNodeQueryMessage> = addr.recipient::<DispatcherNodeQueryMessage> ();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::PublicKey (Key::new (&b"booga"[..])),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(cryptde.public_key()),
                    last_data: false,
                    sequence_number: None,
                    data: Vec::new(),
                },
                recipient,
            }).unwrap();

            system.run ();
        });

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 1);
        let message = recording.get_record::<DispatcherNodeQueryResponse>(0);
        assert_eq!(message.result, None);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_none_when_key_query_matches_no_configured_data () {
        let cryptde = cryptde ();
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new ("neighborhood_sends_node_query_response_with_none_when_key_query_matches_no_configured_data");
            let addr: Addr<Syn, Recorder> = recorder.start();
            let recipient: Recipient<Syn, DispatcherNodeQueryResponse> = addr.recipient::<DispatcherNodeQueryResponse>();

            let subject = Neighborhood::new(cryptde, NeighborhoodConfig {
                neighbor_configs: vec! (
                    (Key::new (&b"booga"[..]), NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap(), &vec! (1234, 2345))),
                ),
                bootstrap_configs: vec! (),
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
                clandestine_port_list: vec! (5678),
            });
            let addr: Addr<Syn, Neighborhood> = subject.start ();
            let sub: Recipient<Syn, DispatcherNodeQueryMessage> = addr.recipient::<DispatcherNodeQueryMessage> ();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::PublicKey(Key::new(&b"blah"[..])),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(cryptde.public_key()),
                    last_data: false,
                    sequence_number: None,
                    data: Vec::new(),
                },
                recipient
            }).unwrap();

            system.run ();
        });

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 1);
        let message = recording.get_record::<DispatcherNodeQueryResponse>(0);
        assert_eq!(message.result, None);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_result_when_key_query_matches_configured_data () {
        let cryptde = cryptde ();
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
            let subject = Neighborhood::new(cryptde, NeighborhoodConfig {
                neighbor_configs: vec!(
                    node_record_to_pair(&one_neighbor),
                    node_record_to_pair(&another_neighbor),
                ),
                bootstrap_configs: vec!(),
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec!(5678),
            });
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let sub: Recipient<Syn, DispatcherNodeQueryMessage> = addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::PublicKey(another_neighbor.public_key().clone()),
                context,
                recipient
            }).unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let message = Recording::get::<DispatcherNodeQueryResponse>(&recording_arc, 0);
        assert_eq!(message.result.unwrap(), NodeDescriptor::new (another_neighbor_a.public_key().clone(), Some(another_neighbor_a.node_addr_opt().unwrap().clone())));
        assert_eq!(message.context, context_a);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_none_when_ip_address_query_matches_no_configured_data () {
        let cryptde = cryptde ();
        let (recorder, awaiter, recording_arc) = make_recorder();
        thread::spawn(move || {
            let system = System::new("responds_with_none_when_initially_configured_with_no_data");
            let addr: Addr<Syn, Recorder> = recorder.start();
            let recipient: Recipient<Syn, DispatcherNodeQueryResponse> = addr.recipient::<DispatcherNodeQueryResponse>();
            let subject = Neighborhood::new(cryptde, NeighborhoodConfig {
                neighbor_configs: vec!(
                    (Key::new(&b"booga"[..]), NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec!(1234, 2345))),
                ),
                bootstrap_configs: vec!(),
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str("5.4.3.2").unwrap(),
                clandestine_port_list: vec!(5678),
            });
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let sub: Recipient<Syn, DispatcherNodeQueryMessage> = addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::IpAddress(IpAddr::from_str("2.3.4.5").unwrap()),
                context: TransmitDataMsg {
                    endpoint: Endpoint::Key(cryptde.public_key()),
                    last_data: false,
                    sequence_number: None,
                    data: Vec::new(),
                },
                recipient
            }).unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), 1);
        let message = recording.get_record::<DispatcherNodeQueryResponse>(0);
        assert_eq!(message.result, None);
    }

    #[test]
    fn neighborhood_sends_node_query_response_with_result_when_ip_address_query_matches_configured_data () {
        let cryptde = cryptde ();
        let (recorder, awaiter, recording_arc) = make_recorder();
        let node_record = make_node_record(1234, true, false);
        let node_record_a = node_record.clone();
        let context =  TransmitDataMsg {
            endpoint: Endpoint::Key(cryptde.public_key()),
            last_data: false,
            sequence_number: None,
            data: Vec::new(),
        };
        let context_a = context.clone();
        thread::spawn(move || {
            let system = System::new("responds_with_none_when_initially_configured_with_no_data");
            let addr: Addr<Syn, Recorder> = recorder.start();
            let recipient: Recipient<Syn, DispatcherNodeQueryResponse> = addr.recipient::<DispatcherNodeQueryResponse>();
            let another_node_record = make_node_record(2345, true, false);
            let subject = Neighborhood::new(cryptde, NeighborhoodConfig {
                neighbor_configs: vec!(
                    (node_record.public_key().clone(), node_record.node_addr_opt().unwrap().clone()),
                    (another_node_record.public_key().clone(), another_node_record.node_addr_opt().unwrap().clone()),
                ),
                bootstrap_configs: vec!(),
                is_bootstrap_node: false,
                local_ip_addr: node_record.node_addr_opt().as_ref().unwrap().ip_addr(),
                clandestine_port_list: node_record.node_addr_opt().as_ref().unwrap().ports().clone(),
            });
            let addr: Addr<Syn, Neighborhood> = subject.start();
            let sub: Recipient<Syn, DispatcherNodeQueryMessage> = addr.recipient::<DispatcherNodeQueryMessage>();

            sub.try_send(DispatcherNodeQueryMessage {
                query: NodeQueryMessage::IpAddress(IpAddr::from_str("1.2.3.4").unwrap()),
                context,
                recipient
            }).unwrap();

            system.run();
        });

        awaiter.await_message_count(1);
        let message = Recording::get::<DispatcherNodeQueryResponse>(&recording_arc, 0);

        assert_eq! (message.result.unwrap(), NodeDescriptor::new (node_record_a.public_key().clone(), Some(node_record_a.node_addr_opt().unwrap().clone())));
        assert_eq!(message.context, context_a);
    }

    #[test]
    fn neighborhood_does_not_gossip_when_db_does_not_change() {
        init_test_logging();
        let cryptde = cryptde ();
        let bootstrap_node = make_node_record(5648, true, true);
        let this_node = NodeRecord::new_for_tests (&cryptde.public_key (), Some (&NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (1234))), false);
        let one_neighbor = make_node_record (2345, true, false);
        let gossip = GossipBuilder::new ().node (&one_neighbor, true).build ();
        let serialized_gossip = PlainData::new (&serde_cbor::ser::to_vec (&gossip).unwrap ()[..]);
        let cores_package = ExpiredCoresPackagePackage { expired_cores_package: ExpiredCoresPackage::new (make_meaningless_route (), serialized_gossip), sender_ip: IpAddr::from_str("1.2.3.4").unwrap() };
        let hopper = Recorder::new ();
        let hopper_recording = hopper.get_recording ();
        let this_node_inside = this_node.clone ();
        let one_neighbor_inside = one_neighbor.clone ();
        thread::spawn (move || {
            let system = System::new ("");
            let mut subject = Neighborhood::new (cryptde, NeighborhoodConfig {
                neighbor_configs: vec! (),
                bootstrap_configs: vec! ((bootstrap_node.public_key().clone(), bootstrap_node.node_addr_opt().unwrap())),
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
                clandestine_port_list: vec! (1234),
            });
            subject.neighborhood_database.add_node (&one_neighbor_inside).unwrap ();
            subject.neighborhood_database.add_neighbor (this_node_inside.public_key (), one_neighbor_inside.public_key ()).unwrap ();
            subject.neighborhood_database.add_neighbor (one_neighbor_inside.public_key (), this_node_inside.public_key ()).unwrap ();
            let addr: Addr<Syn, Neighborhood> = subject.start ();
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap ();

            let sub: Recipient<Syn, ExpiredCoresPackagePackage> = addr.recipient::<ExpiredCoresPackagePackage> ();
            sub.try_send (cores_package).unwrap ();

            system.run ();
        });
        TestLogHandler::new().await_log_containing(&format!("Finished processing Gossip about 1 Nodes"), 500);
        let locked_recording = hopper_recording.lock ().unwrap ();
        assert_eq!(0, locked_recording.len());
    }

    #[test]
    fn node_gossips_only_to_immediate_neighbors () {
        init_test_logging();
        let cryptde = cryptde ();
        let mut this_node = NodeRecord::new_for_tests (&cryptde.public_key (), Some (&NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (1234))), true);
        let mut far_neighbor = make_node_record(1234, true, false);
        let mut gossip_neighbor = make_node_record (4567, true, false);
        gossip_neighbor.neighbors_mut ().push (this_node.public_key ().clone ());
        gossip_neighbor.neighbors_mut ().push (far_neighbor.public_key ().clone ());
        far_neighbor.neighbors_mut ().push (gossip_neighbor.public_key ().clone ());

        let gossip = GossipBuilder::new ().node (&gossip_neighbor, true).node(&far_neighbor, false).build ();
        let serialized_gossip = PlainData::new (&serde_cbor::ser::to_vec (&gossip).unwrap ()[..]);
        let cores_package = ExpiredCoresPackagePackage { expired_cores_package: ExpiredCoresPackage::new (make_meaningless_route (), serialized_gossip), sender_ip: IpAddr::from_str("1.2.3.4").unwrap() };
        let hopper = Recorder::new ();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording = hopper.get_recording ();
        let this_node_inside = this_node.clone ();
        thread::spawn (move || {
            let system = System::new ("");
            let mut subject = Neighborhood::new (cryptde, NeighborhoodConfig {
                neighbor_configs: vec! (),
                bootstrap_configs: vec! (),
                is_bootstrap_node: this_node_inside.is_bootstrap_node(),
                local_ip_addr: this_node_inside.node_addr_opt().unwrap ().ip_addr(),
                clandestine_port_list: this_node_inside.node_addr_opt().unwrap ().ports(),
            });
            let addr: Addr<Syn, Neighborhood> = subject.start ();
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap ();

            let sub: Recipient<Syn, ExpiredCoresPackagePackage> = addr.recipient::<ExpiredCoresPackagePackage> ();
            sub.try_send (cores_package).unwrap ();

            system.run ();
        });
        TestLogHandler::new().await_log_containing(&format!("Finished processing Gossip about 2 Nodes"), 500);
        let locked_recording = hopper_recording.lock ().unwrap ();
        assert_eq!(1, locked_recording.len());
        let package = locked_recording.get_record (0);
        assert_eq!(&find_package_target (package), gossip_neighbor.public_key ());
    }
}
