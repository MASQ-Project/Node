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
use sub_lib::neighborhood::NodeQueryMessage;
use sub_lib::neighborhood::NodeDescriptor;
use actix::MessageResult;
use sub_lib::neighborhood::RouteQueryMessage;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::route::RouteSegment;
use sub_lib::hopper::IncipientCoresPackage;
use actix::Recipient;
use neighborhood_database::NeighborhoodDatabase;
use gossip_acceptor::GossipAcceptor;
use sub_lib::neighborhood::NeighborhoodConfig;
use neighborhood_database::NodeRecord;
use gossip::Gossip;
use temporary_bootstrap_gossip_acceptor::TemporaryBootstrapGossipAcceptor;
use gossip_producer::GossipProducerReal;
use gossip_producer::GossipProducer;
use sub_lib::logger::Logger;
use sub_lib::neighborhood::BootstrapNeighborhoodNowMessage;
use gossip_acceptor::GossipAcceptorReal;
use sub_lib::neighborhood::RouteType;
use sub_lib::neighborhood::TargetType;
use sub_lib::neighborhood::sentinel_ip_addr;

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

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.hopper = Some (msg.peer_actors.hopper.from_hopper_client);
        ()
    }
}

impl Handler<BootstrapNeighborhoodNowMessage> for Neighborhood {
    type Result = ();

    fn handle (&mut self, _msg: BootstrapNeighborhoodNowMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.neighborhood_database.keys().into_iter()
        .flat_map(|key_ref| self.neighborhood_database.node_by_key(key_ref))
        .filter(|node_record| node_record.is_bootstrap_node())
        .for_each(|bootstrap_node| {
            let gossip = self.gossip_producer.produce(&self.neighborhood_database, bootstrap_node.public_key());
            let route = self.create_single_hop_route(bootstrap_node.public_key());
            let package = IncipientCoresPackage::new(route, gossip, bootstrap_node.public_key());
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

impl Handler<RouteQueryMessage> for Neighborhood {
    type Result = MessageResult<RouteQueryMessage>;

    fn handle(&mut self, msg: RouteQueryMessage, _ctx: &mut Self::Context) -> <Self as Handler<RouteQueryMessage>>::Result {
        if msg.minimum_hop_count == 0 {
            MessageResult (Some (self.zero_hop_route ()))
        }
        else {
            MessageResult (match msg.route_type {
                RouteType::OneWay => self.make_one_way_route(msg),
                RouteType::RoundTrip => self.make_round_trip_route(msg)
            })
        }
    }
}

impl Handler<ExpiredCoresPackage> for Neighborhood {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackage, _ctx: &mut Self::Context) -> Self::Result {
        let incoming_gossip: Gossip = match msg.payload() {
            Ok (p) => p,
            Err (_) => {self.logger.error (format! ("Unintelligible Gossip message received: ignoring")); return ();},
        };
        self.gossip_acceptor.handle (&mut self.neighborhood_database, incoming_gossip);

        if self.neighborhood_database.root().is_bootstrap_node() {
            self.neighborhood_database.keys().into_iter().for_each(|key_ref| {
                if key_ref != self.neighborhood_database.root().public_key() {
                    let gossip = self.gossip_producer.produce(&self.neighborhood_database, key_ref);
                    let route = self.create_single_hop_route(key_ref);
                    let package = IncipientCoresPackage::new(route, gossip, key_ref);
                    self.hopper.as_ref().expect("unbound hopper").try_send(package).expect("hopper is dead");
                }
            });
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
        let gossip_acceptor : Box<GossipAcceptor> = if config.is_bootstrap_node {
            Box::new (TemporaryBootstrapGossipAcceptor::new ())
        } else {
            Box::new (GossipAcceptorReal::new())
        };
        let gossip_producer = Box::new (GossipProducerReal::new ());
        let local_node_addr = NodeAddr::new (&config.local_ip_addr, &config.clandestine_port_list);
        let mut neighborhood_database = NeighborhoodDatabase::new (&cryptde.public_key(), &local_node_addr, config.is_bootstrap_node);

        let add_node = |neighborhood_database: &mut NeighborhoodDatabase, neighbor: &(Key, NodeAddr), is_bootstrap_node: bool| {
            let (key, node_addr) = neighbor;
            let root_key_ref = &neighborhood_database.root().public_key().clone();
            neighborhood_database.add_node(&NodeRecord::new(&key, Some(&node_addr), is_bootstrap_node)).expect(&format! ("Database already contains node {:?}", key));
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
            from_hopper: addr.clone ().recipient::<ExpiredCoresPackage>(),
        }
    }

    fn create_single_hop_route(&self, destination: &Key) -> Route {
        // TODO While the database is forced linear, the route sought here doesn't exist in the database and has to be hacked up here.
        Route::new(vec! (RouteSegment::new(vec! (&self.cryptde.public_key(), destination), Component::Neighborhood)), self.cryptde).expect("route creation error")
    }

    fn zero_hop_route (&self) -> Route {
        Route::new(vec! (
            RouteSegment::new(vec! (&self.cryptde.public_key(), &self.cryptde.public_key ()), Component::ProxyClient),
            RouteSegment::new(vec! (&self.cryptde.public_key(), &self.cryptde.public_key()), Component::ProxyServer)
        ), self.cryptde).expect("Couldn't create route")
    }

    fn make_one_way_route (&self, msg: RouteQueryMessage) -> Option<Route> {
        match self.make_route_segment(&self.cryptde.public_key(), msg.target_key_opt.as_ref(), msg.target_type, msg.minimum_hop_count, msg.target_component) {
            Some(segment) => Some (Route::new(vec! (segment), self.cryptde).expect("bad route")),
            None => None
        }
    }

    fn make_round_trip_route (&self, msg: RouteQueryMessage) -> Option<Route> {
        let local_target_type = if self.neighborhood_database.root().is_bootstrap_node() { TargetType::Bootstrap } else { TargetType::Standard };
        if let Some(over) = self.make_route_segment(
            &self.cryptde.public_key(),
            msg.target_key_opt.as_ref(),
            msg.target_type,
            msg.minimum_hop_count,
            msg.target_component
        ) {
            if let Some (back) = self.make_route_segment(
                over.keys.last().expect("Empty segment"),
                Some(&self.cryptde.public_key()),
                local_target_type,
                msg.minimum_hop_count,
                msg.return_component_opt.expect("No return component")
            ) {
                return Some(Route::new(vec! (over, back), self.cryptde).expect("Bad route"));
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
    use futures::future::Future;
    use serde_cbor;
    use test_utils::test_utils::cryptde;
    use neighborhood_test_utils::make_node_record;
    use gossip::GossipBuilder;
    use std::thread;
    use test_utils::test_utils::Recorder;
    use test_utils::test_utils::make_peer_actors_from;
    use test_utils::test_utils::make_meaningless_route;
    use sub_lib::cryptde::PlainData;
    use sub_lib::cryptde_null::CryptDENull;
    use gossip::Gossip;
    use neighborhood_test_utils::vec_to_set;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::sync::Arc;
    use gossip_acceptor::GossipAcceptorReal;
    use test_utils::test_utils::init_test_logging;
    use test_utils::test_utils::TestLogHandler;
    use gossip::GossipNodeRecord;
    use sub_lib::neighborhood::sentinel_ip_addr;

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
        let expected_route = Route::new(vec! (
            RouteSegment::new(vec! (&cryptde.public_key(), &cryptde.public_key()), Component::ProxyClient),
            RouteSegment::new(vec! (&cryptde.public_key(), &cryptde.public_key()), Component::ProxyServer)
        ), cryptde).unwrap ();
        assert_eq! (result, expected_route);
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
        let expected_route = Route::new(vec! (
            segment (vec! (p, q, r, s, b), Component::Neighborhood)
        ), cryptde).unwrap ();
        assert_eq! (result, expected_route);

        let result = data_route.wait ().unwrap ().unwrap ();
        let expected_route = Route::new(vec! (
            segment (vec! (p, q, r), Component::ProxyClient),
            segment (vec! (r, q, p), Component::ProxyServer),
        ), cryptde).unwrap ();
        assert_eq! (result, expected_route);
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
            assert_eq! (routes.contains (&expected_keys), true, "{:?}", routes);
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
        let cores_package = ExpiredCoresPackage::new (make_meaningless_route (), PlainData::new (&b"booga"[..]));
        let system = System::new ("");
        let subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! (),
            is_bootstrap_node: false,
            local_ip_addr: sentinel_ip_addr(),
            clandestine_port_list: vec! (),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, ExpiredCoresPackage> = addr.recipient::<ExpiredCoresPackage> ();

        sub.try_send (cores_package).unwrap ();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        TestLogHandler::new ().exists_log_containing ("ERROR: Neighborhood: Unintelligible Gossip message received: ignoring");
    }

    #[test]
    fn bootstrap_node_receives_gossip_and_replies () {
        let cryptde = cryptde ();
        let this_node = NodeRecord::new (&cryptde.public_key (), Some (&NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (1234))), true);
        let one_neighbor = make_node_record (2345, true, false);
        let gossip_neighbor = make_node_record (4567, true, false);
        let gossip = GossipBuilder::new ().node (&gossip_neighbor, true).build ();
        let serialized_gossip = PlainData::new (&serde_cbor::ser::to_vec (&gossip).unwrap ()[..]);
        let cores_package = ExpiredCoresPackage::new (make_meaningless_route (), serialized_gossip);
        let hopper = Recorder::new ();
        let hopper_awaiter = hopper.get_awaiter ();
        let hopper_recording = hopper.get_recording ();
        let this_node_inside = this_node.clone ();
        let one_neighbor_inside = one_neighbor.clone ();
        thread::spawn (move || {
            let system = System::new ("");
            let mut subject = Neighborhood::new (cryptde, NeighborhoodConfig {
                neighbor_configs: vec! (),
                bootstrap_configs: vec! (),
                is_bootstrap_node: true,
                local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
                clandestine_port_list: vec! (1234),
            });
            subject.neighborhood_database.add_node (&one_neighbor_inside).unwrap ();
            subject.neighborhood_database.add_neighbor (this_node_inside.public_key (), one_neighbor_inside.public_key ()).unwrap ();
            subject.neighborhood_database.add_neighbor (one_neighbor_inside.public_key (), this_node_inside.public_key ()).unwrap ();
            let addr: Addr<Syn, Neighborhood> = subject.start ();
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            addr.try_send(BindMessage { peer_actors }).unwrap ();

            let sub: Recipient<Syn, ExpiredCoresPackage> = addr.recipient::<ExpiredCoresPackage> ();
            sub.try_send (cores_package).unwrap ();

            system.run ();
        });
        hopper_awaiter.await_message_count (2);
        let locked_recording = hopper_recording.lock ().unwrap ();
        let package_refs = vec! (locked_recording.get_record (0), locked_recording.get_record (1));
        let checked_keys: Arc<Mutex<HashSet<&Key>>> = Arc::new (Mutex::new (HashSet::new ()));
        let checked_keys_inside = checked_keys.clone ();
        package_refs.into_iter ().for_each (|package| {
            if &find_package_target (package) == gossip_neighbor.public_key () {
                checked_keys_inside.lock ().unwrap ().insert (one_neighbor.public_key ());
                check_outgoing_package(package, &one_neighbor, &gossip_neighbor);
            }
            else {
                checked_keys_inside.lock ().unwrap ().insert (gossip_neighbor.public_key ());
                check_outgoing_package(package, &gossip_neighbor, &one_neighbor);
            }
        });
        assert_eq! (checked_keys.lock ().unwrap ().len (), 2);
    }

    #[test]
    fn standard_node_requests_bootstrap_properly () {
        let cryptde = cryptde ();
        let this_node = NodeRecord::new (&cryptde.public_key (), Some (&NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (1234))), false);
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
        assert_eq! (gossip.node_records, vec! (GossipNodeRecord::from(&this_node, true)));
        assert_eq! (gossip.neighbor_pairs, vec! ());
    }

    #[test]
    fn standard_node_accepts_gossip_properly() {
        let cryptde = cryptde ();
        let this_node = NodeRecord::new (&cryptde.public_key (), Some (&NodeAddr::new (&IpAddr::from_str ("5.4.3.2").unwrap (), &vec! (1234))), false);
        let one_neighbor = make_node_record (2345, false, false);
        let bootstrap_neighbor = make_node_record (4567, true, true);
        let gossip = GossipBuilder::new ()
            .node (&one_neighbor, false)
            .node (&bootstrap_neighbor, true)
            .neighbor_pair (one_neighbor.public_key (), bootstrap_neighbor.public_key ())
            .build ();
        let serialized_gossip = PlainData::new (&serde_cbor::ser::to_vec (&gossip).unwrap ()[..]);
        let cores_package = ExpiredCoresPackage::new (make_meaningless_route (), serialized_gossip);
        let mut subject = Neighborhood::new (cryptde, NeighborhoodConfig {
            neighbor_configs: vec! (),
            bootstrap_configs: vec! ((bootstrap_neighbor.public_key ().clone (), bootstrap_neighbor.node_addr_opt ().unwrap ().clone ())),
            is_bootstrap_node: false,
            local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
            clandestine_port_list: vec! (1234),
        });

        // Warning: creating (unsafe!) mutable reference to Context<Neighborhood> at address 0. Will
        // pop a segmentation fault if used. Wouldn't do this, except that otherwise we can't access
        // the database to see the changes once .start() has been called on the actor.
        let null_ptr = 0 as *mut Context<Neighborhood>;
        let null_ctx_ref = unsafe {&mut *null_ptr as &mut Context<Neighborhood>};

        subject.handle (cores_package, null_ctx_ref);

        let database = subject.neighborhood_database;
        assert_eq!(database.keys (), vec_to_set(vec! (this_node.public_key (), one_neighbor.public_key (), bootstrap_neighbor.public_key ())));
        assert_eq!(database.node_by_key(this_node.public_key()).unwrap(), &this_node);
        assert_eq!(database.node_by_key(one_neighbor.public_key()).unwrap(), &one_neighbor);
        assert_eq!(database.node_by_key(bootstrap_neighbor.public_key()).unwrap(), &bootstrap_neighbor);
        check_is_neighbor(&database, &this_node, &bootstrap_neighbor);
        check_is_neighbor(&database, &one_neighbor, &bootstrap_neighbor);
    }

    fn node_record_to_pair (node_record_ref: &NodeRecord) -> (Key, NodeAddr) {
        (node_record_ref.public_key ().clone (), node_record_ref.node_addr_opt ().unwrap ().clone ())
    }

    fn find_package_target (package: &IncipientCoresPackage) -> Key {
        let mut route = package.route.clone ();
        let hop = route.shift (&CryptDENull::other_key(&cryptde ().public_key ()), cryptde()).unwrap ();
        hop.public_key
    }

    fn check_direct_route_to (route: &Route, destination: &Key) {
        let mut route = route.clone ();
        let hop = route.shift(&CryptDENull::other_key(&cryptde().public_key()), cryptde()).unwrap();
        assert_eq!(&hop.public_key, destination);
        assert_eq!(hop.component, Component::Hopper);
        let hop = route.shift(&CryptDENull::other_key(destination), cryptde()).unwrap();
        assert_eq!(hop.component, Component::Neighborhood);
    }

    fn check_outgoing_package(cores_package: &IncipientCoresPackage, neighbor: &NodeRecord, target: &NodeRecord) -> NeighborhoodDatabase {
        check_direct_route_to (&cores_package.route, target.public_key ());
        assert_eq!(&cores_package.payload_destination_key, target.public_key());
        let deserialized_payload: Gossip = serde_cbor::de::from_slice(&cores_package.payload.data[..]).unwrap();
        let mut database = NeighborhoodDatabase::new(target.public_key(), target.node_addr_opt().unwrap(), false);
        GossipAcceptorReal::new().handle(&mut database, deserialized_payload);
        assert_eq!(database.keys(), vec_to_set(vec!(neighbor.public_key(), target.public_key())));
        assert_eq!(database.node_by_key(neighbor.public_key()).unwrap(), neighbor);
        assert_eq!(database.node_by_key(target.public_key()).unwrap(), target);
        check_is_neighbor(&database, neighbor, target);
        check_is_neighbor(&database, target, neighbor);
        database
    }

    fn check_is_neighbor(database: &NeighborhoodDatabase, from: &NodeRecord, to: &NodeRecord) {
        assert_eq! (database.has_neighbor (from.public_key (), to.public_key ()), true, "Node {:?} should have {:?} as its neighbor, but doesn't: {:?}", from.public_key (), to.public_key (), database);
    }

    fn dual_edge_func (db: &mut NeighborhoodDatabase, a: &NodeRecord, b: &NodeRecord) {
        db.add_neighbor(a.public_key(), b.public_key()).unwrap();
        db.add_neighbor(b.public_key(), a.public_key()).unwrap();
    }
}
