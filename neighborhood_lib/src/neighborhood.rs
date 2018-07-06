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

// TODO: Neighborhood should be sensitive to attempts to use it in a decentralized fashion when it
// has not been given enough data to do so. If this happens, it should panic with a clear message,
// rather than continuing to operate and producing distant, hard-to-understand errors.

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
            let route = Route::new(vec! (
                RouteSegment::new(vec! (&self.cryptde.public_key(), &self.cryptde.public_key ()), Component::ProxyClient),
                RouteSegment::new(vec! (&self.cryptde.public_key(), &self.cryptde.public_key()), Component::ProxyServer)
            ), self.cryptde).expect("Couldn't create route");
            return MessageResult(Some(route));
        }
        MessageResult(None)
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

        self.neighborhood_database.keys().into_iter().for_each(|key_ref| {
            if key_ref != self.neighborhood_database.root().public_key() {
                let gossip = self.gossip_producer.produce(&self.neighborhood_database, key_ref);
                // TODO This will eventually be requested from the route generator rather than computed here
                let route = Route::new(vec! (RouteSegment::new(vec! (&self.cryptde.public_key(), key_ref), Component::Neighborhood)), self.cryptde).expect("route creation error");
                let package = IncipientCoresPackage::new(route, gossip, key_ref);
                self.hopper.as_ref().expect("unbound hopper").try_send(package).expect("hopper is dead");
            }
        });
        ()
    }
}

impl Neighborhood {
    pub fn new(cryptde: &'static CryptDE, config: NeighborhoodConfig) -> Self {
        let gossip_acceptor = Box::new (TemporaryBootstrapGossipAcceptor::new ());
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
            node_query: addr.clone ().recipient::<NodeQueryMessage>(),
            route_query: addr.clone ().recipient::<RouteQueryMessage>(),
            from_hopper: addr.clone ().recipient::<ExpiredCoresPackage>(),
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

        assert_eq! (root_node_record_ref.has_neighbor(one_node.public_key()), true);
        assert_eq! (root_node_record_ref.has_neighbor(another_node.public_key()), true);

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
            local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
            clandestine_port_list: vec! (5678),
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
            local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
            clandestine_port_list: vec! (5678),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage> ();

        let future = sub.send (RouteQueryMessage {minimum_hop_count: 5});

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
            local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
            clandestine_port_list: vec! (5678),
        });
        let addr: Addr<Syn, Neighborhood> = subject.start ();
        let sub: Recipient<Syn, RouteQueryMessage> = addr.recipient::<RouteQueryMessage> ();

        let future = sub.send (RouteQueryMessage {minimum_hop_count: 0});

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap ();
        system.run ();
        let result = future.wait ().unwrap ().unwrap ();
        let expected_route = Route::new(vec! (
            RouteSegment::new(vec! (&cryptde.public_key(), &cryptde.public_key()), Component::ProxyClient),
            RouteSegment::new(vec! (&cryptde.public_key(), &cryptde.public_key()), Component::ProxyServer)
        ), cryptde).unwrap ();
        assert_eq! (result, expected_route);
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
            is_bootstrap_node: true,
            local_ip_addr: IpAddr::from_str ("5.4.3.2").unwrap (),
            clandestine_port_list: vec! (1234),
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
        let unlocked_recording = hopper_recording.lock ().unwrap ();
        let package_refs = vec! (unlocked_recording.get_record (0), unlocked_recording.get_record (1));
        let checked_keys: Arc<Mutex<HashSet<&Key>>> = Arc::new (Mutex::new (HashSet::new ()));
        let checked_keys_inside = checked_keys.clone ();
        package_refs.into_iter ().for_each (|package| {
            let database = if &find_package_target (package) == gossip_neighbor.public_key () {
                checked_keys_inside.lock ().unwrap ().insert (one_neighbor.public_key ());
                check_outgoing_package(package, &this_node, &one_neighbor, &gossip_neighbor)
            }
            else {
                checked_keys_inside.lock ().unwrap ().insert (gossip_neighbor.public_key ());
                check_outgoing_package(package, &this_node, &gossip_neighbor, &one_neighbor)
            };
            check_is_neighbor(&database, &this_node, &one_neighbor);
            check_not_neighbor(&database, &this_node, &gossip_neighbor);
        });
        assert_eq! (checked_keys.lock ().unwrap ().len (), 2);
    }

    fn node_record_to_pair (node_record_ref: &NodeRecord) -> (Key, NodeAddr) {
        (node_record_ref.public_key ().clone (), node_record_ref.node_addr_opt ().unwrap ().clone ())
    }

    fn find_package_target (package: &IncipientCoresPackage) -> Key {
        let mut route = package.route.clone ();
        let hop = route.shift (&CryptDENull::other_key(&cryptde ().public_key ()), cryptde()).unwrap ();
        hop.public_key
    }

    fn check_outgoing_package(cores_package: &IncipientCoresPackage, this_node: &NodeRecord, neighbor: &NodeRecord, target: &NodeRecord) -> NeighborhoodDatabase {
        let mut route = cores_package.route.clone();
        let hop = route.shift(&CryptDENull::other_key(&cryptde().public_key()), cryptde()).unwrap();
        assert_eq!(&hop.public_key, target.public_key());
        assert_eq!(hop.component, Component::Hopper);
        let hop = route.shift(&CryptDENull::other_key(target.public_key()), cryptde()).unwrap();
        assert_eq!(hop.component, Component::Neighborhood);
        assert_eq!(&cores_package.payload_destination_key, target.public_key());
        let deserialized_payload: Gossip = serde_cbor::de::from_slice(&cores_package.payload.data[..]).unwrap();
        let mut database = NeighborhoodDatabase::new(target.public_key(), target.node_addr_opt().unwrap(), false);
        GossipAcceptorReal::new().handle(&mut database, deserialized_payload);
        assert_eq!(database.keys(), vec_to_set(vec!(this_node.public_key(), neighbor.public_key(), target.public_key())));
        assert_eq!(database.node_by_key(this_node.public_key()).unwrap(), this_node);
        assert_eq!(database.node_by_key(neighbor.public_key()).unwrap(), neighbor);
        assert_eq!(database.node_by_key(target.public_key()).unwrap(), target);
        check_is_neighbor(&database, neighbor, target);
        check_is_neighbor(&database, neighbor, this_node);
        check_is_neighbor(&database, target, this_node);
        check_is_neighbor(&database, target, neighbor);
        database
    }

    fn check_is_neighbor(database: &NeighborhoodDatabase, from: &NodeRecord, to: &NodeRecord) {
        assert_eq! (database.has_neighbor (from.public_key (), to.public_key ()), true, "Node {:?} should have {:?} as its neighbor, but doesn't: {:?}", from.public_key (), to.public_key (), database);
    }

    fn check_not_neighbor (database: &NeighborhoodDatabase, from: &NodeRecord, to: &NodeRecord) {
        assert_eq! (database.has_neighbor (from.public_key (), to.public_key ()), false, "Node {:?} should not have {:?} as its neighbor, but does: {:?}", from.public_key (), to.public_key (), database);
    }
}
