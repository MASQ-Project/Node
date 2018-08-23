// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use std::sync::mpsc;
use actix::Actor;
use actix::Addr;
use actix::Recipient;
use actix::Syn;
use actix::System;
use bootstrapper::BootstrapperConfig;
use dispatcher::Dispatcher;
use hopper_lib::hopper::Hopper;
use neighborhood_lib::neighborhood::Neighborhood;
use proxy_client_lib::proxy_client::ProxyClient;
use proxy_server_lib::proxy_server::ProxyServer;
use stream_handler_pool::StreamHandlerPool;
use stream_handler_pool::StreamHandlerPoolSubs;
use stream_messages::PoolBindMessage;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::dispatcher::DispatcherSubs;
use sub_lib::hopper::HopperSubs;
use sub_lib::neighborhood::NeighborhoodSubs;
use sub_lib::peer_actors::BindMessage;
use sub_lib::peer_actors::PeerActors;
use sub_lib::proxy_client::ProxyClientSubs;
use sub_lib::proxy_server::ProxyServerSubs;
use bootstrapper;
use sub_lib::neighborhood::NeighborhoodConfig;
use std::sync::mpsc::Sender;
use sub_lib::neighborhood::BootstrapNeighborhoodNowMessage;
use discriminator::DiscriminatorFactory;
use std::thread;

pub trait ActorSystemFactory: Send {
    fn make_and_start_actors(&self, config: BootstrapperConfig, actor_factory: Box<ActorFactory>) -> StreamHandlerPoolSubs;
}

pub struct ActorSystemFactoryReal {}

impl ActorSystemFactory for ActorSystemFactoryReal {
    fn make_and_start_actors(&self, config: BootstrapperConfig, actor_factory: Box<ActorFactory>) -> StreamHandlerPoolSubs {
        let cryptde: &'static CryptDENull = unsafe {
            bootstrapper::CRYPT_DE_OPT.as_ref().expect("Internal error")
        };
        let (tx, rx) = mpsc::channel();

        // TODO: this thread::spawn goes away with actix 0.7
        thread::spawn(move || {
            let system = System::new("SubstratumNode");

            ActorSystemFactoryReal::prepare_initial_messages(cryptde, config, actor_factory, tx);

            // TODO: System::new and system.run() are handled by actix::run in actix 0.7+ and might not live here
            //run the actor system
            system.run()
        });

        rx.recv().expect("Internal error: actor-system init thread died before initializing StreamHandlerPool subscribers")
    }
}

impl ActorSystemFactoryReal {

    fn prepare_initial_messages(cryptde: &'static CryptDE, config: BootstrapperConfig, actor_factory: Box<ActorFactory>, tx: Sender<StreamHandlerPoolSubs>) {
        // make all the actors
        let (dispatcher_subs, pool_bind_sub) = actor_factory.make_and_start_dispatcher();
        let proxy_server_subs = actor_factory.make_and_start_proxy_server(cryptde, config.neighborhood_config.is_decentralized());
        let proxy_client_subs = actor_factory.make_and_start_proxy_client(cryptde, config.dns_servers);
        let hopper_subs = actor_factory.make_and_start_hopper(cryptde, config.neighborhood_config.is_bootstrap_node);
        let neighborhood_subs = actor_factory.make_and_start_neighborhood(cryptde, config.neighborhood_config);
        let stream_handler_pool_subs = actor_factory.make_and_start_stream_handler_pool(config.clandestine_discriminator_factories);

        // collect all the subs
        let peer_actors = PeerActors {
            dispatcher: dispatcher_subs.clone(),
            proxy_server: proxy_server_subs,
            proxy_client: proxy_client_subs,
            hopper: hopper_subs,
            neighborhood: neighborhood_subs.clone(),
        };

        //bind all the actors
        peer_actors.dispatcher.bind.try_send(BindMessage { peer_actors: peer_actors.clone() }).expect("Dispatcher is dead");
        peer_actors.proxy_server.bind.try_send(BindMessage { peer_actors: peer_actors.clone() }).expect("Proxy Server is dead");
        peer_actors.proxy_client.bind.try_send(BindMessage { peer_actors: peer_actors.clone() }).expect("Proxy Client is dead");
        peer_actors.hopper.bind.try_send(BindMessage { peer_actors: peer_actors.clone() }).expect("Hopper is dead");
        peer_actors.neighborhood.bind.try_send(BindMessage { peer_actors: peer_actors.clone() }).expect("Neighborhood is dead");
        stream_handler_pool_subs.bind.try_send(PoolBindMessage {
            dispatcher_subs: dispatcher_subs.clone(),
            stream_handler_pool_subs: stream_handler_pool_subs.clone(),
            neighborhood_subs: neighborhood_subs.clone(),
        }).expect("Stream Handler Pool is dead");
        pool_bind_sub.try_send(PoolBindMessage {
            dispatcher_subs,
            stream_handler_pool_subs: stream_handler_pool_subs.clone(),
            neighborhood_subs: neighborhood_subs.clone(),
        }).expect("Dispatcher is dead");
        peer_actors.neighborhood.bootstrap.try_send (BootstrapNeighborhoodNowMessage {}).expect ("Neighborhood is dead");

        //send out the stream handler pool subs (to be bound to listeners)
        tx.send(stream_handler_pool_subs).ok();
    }
}

pub trait ActorFactory: Send {
    fn make_and_start_dispatcher(&self) -> (DispatcherSubs, Recipient<Syn, PoolBindMessage>);
    fn make_and_start_proxy_server(&self, cryptde: &'static CryptDE, is_decentralized: bool) -> ProxyServerSubs;
    fn make_and_start_hopper(&self, cryptde: &'static CryptDE, is_bootstrap_node: bool) -> HopperSubs;
    fn make_and_start_neighborhood(&self, cryptde: &'static CryptDE, config: NeighborhoodConfig) -> NeighborhoodSubs;
    fn make_and_start_stream_handler_pool(&self, clandestine_discriminator_factories: Vec<Box<DiscriminatorFactory>>) -> StreamHandlerPoolSubs;
    fn make_and_start_proxy_client(&self, cryptde: &'static CryptDE, dns_servers: Vec<SocketAddr>) -> ProxyClientSubs;
}

pub struct ActorFactoryReal {}

impl ActorFactory for ActorFactoryReal {
    fn make_and_start_dispatcher(&self) -> (DispatcherSubs, Recipient<Syn, PoolBindMessage>) {
        let dispatcher = Dispatcher::new();
        let addr: Addr<Syn, Dispatcher> = dispatcher.start();
        (Dispatcher::make_subs_from(&addr), addr.recipient::<PoolBindMessage> ())
    }

    fn make_and_start_proxy_server(&self, cryptde: &'static CryptDE, is_decentralized: bool) -> ProxyServerSubs {
        let proxy_server = ProxyServer::new(cryptde, is_decentralized);
        let addr: Addr<Syn, ProxyServer> = proxy_server.start();
        ProxyServer::make_subs_from(&addr)
    }

    fn make_and_start_hopper(&self, cryptde: &'static CryptDE, is_bootstrap_node: bool) -> HopperSubs {
        let hopper = Hopper::new(cryptde, is_bootstrap_node);
        let addr: Addr<Syn, Hopper> = hopper.start();
        Hopper::make_subs_from(&addr)
    }

    fn make_and_start_neighborhood(&self, cryptde: &'static CryptDE, config: NeighborhoodConfig) -> NeighborhoodSubs {
        let neighborhood = Neighborhood::new (cryptde, config);
        let addr: Addr<Syn, Neighborhood> = neighborhood.start ();
        Neighborhood::make_subs_from (&addr)
    }

    fn make_and_start_stream_handler_pool(&self, clandestine_discriminator_factories: Vec<Box<DiscriminatorFactory>>) -> StreamHandlerPoolSubs {
        let pool = StreamHandlerPool::new(clandestine_discriminator_factories);
        let addr: Addr<Syn, StreamHandlerPool> = pool.start();
        StreamHandlerPool::make_subs_from(&addr)
    }

    fn make_and_start_proxy_client(&self, cryptde: &'static CryptDE, dns_servers: Vec<SocketAddr>) -> ProxyClientSubs {
        let proxy_client = ProxyClient::new(cryptde, dns_servers);
        let addr: Addr<Syn, ProxyClient> = proxy_client.start();
        ProxyClient::make_subs_from(&addr)
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use test_utils::recorder::Recorder;
    use test_utils::recorder::Recording;
    use std::sync::Mutex;
    use std::sync::Arc;
    use bootstrapper::CRYPT_DE_OPT;
    use sub_lib::dispatcher::InboundClientData;
    use sub_lib::stream_handler_pool::TransmitDataMsg;
    use std::cell::RefCell;
    use sub_lib::hopper::ExpiredCoresPackage;
    use sub_lib::hopper::IncipientCoresPackage;
    use sub_lib::neighborhood::NodeQueryMessage;
    use sub_lib::neighborhood::RouteQueryMessage;
    use stream_messages::AddStreamMsg;
    use stream_messages::RemoveStreamMsg;
    use std::time::Duration;
    use actix::msgs;
    use actix::Arbiter;
    use test_utils::test_utils::cryptde;
    use sub_lib::cryptde::PlainData;
    use sub_lib::neighborhood::DispatcherNodeQueryMessage;
    use sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
    use sub_lib::crash_point::CrashPoint;
    use std::net::Ipv4Addr;
    use std::net::IpAddr;

    struct ActorFactoryMock<'a> {
        dispatcher: RefCell<Option<Recorder>>,
        proxy_client: RefCell<Option<Recorder>>,
        proxy_server: RefCell<Option<Recorder>>,
        hopper: RefCell<Option<Recorder>>,
        neighborhood: RefCell<Option<Recorder>>,
        stream_handler_pool: RefCell<Option<Recorder>>,

        parameters: Parameters<'a>,
    }

    impl<'a> ActorFactory for ActorFactoryMock<'a> {
        fn make_and_start_dispatcher(&self) -> (DispatcherSubs, Recipient<Syn, PoolBindMessage>) {
            let addr: Addr<Syn, Recorder> = ActorFactoryMock::start_recorder (&self.dispatcher);
            let dispatcher_subs = DispatcherSubs {
                ibcd_sub: addr.clone ().recipient::<InboundClientData>(),
                bind: addr.clone ().recipient::<BindMessage>(),
                from_dispatcher_client: addr.clone ().recipient::<TransmitDataMsg>(),
            };
            (dispatcher_subs, addr.recipient::<PoolBindMessage> ())
        }

        fn make_and_start_proxy_server(&self, cryptde: &'a CryptDE, is_decentralized: bool) -> ProxyServerSubs {
            self.parameters.proxy_server_params.lock ().unwrap ().get_or_insert ((cryptde, is_decentralized));
            let addr: Addr<Syn, Recorder> = ActorFactoryMock::start_recorder (&self.proxy_server);
            ProxyServerSubs {
                bind: addr.clone ().recipient::<BindMessage>(),
                from_dispatcher: addr.clone ().recipient::<InboundClientData>(),
                from_hopper: addr.clone ().recipient::<ExpiredCoresPackage>(),
            }
        }

        fn make_and_start_hopper(&self, cryptde: &'a CryptDE, is_bootstrap_node: bool) -> HopperSubs {
            self.parameters.hopper_params.lock ().unwrap ().get_or_insert ((cryptde, is_bootstrap_node));
            let addr: Addr<Syn, Recorder> = ActorFactoryMock::start_recorder (&self.hopper);
            HopperSubs {
                bind: addr.clone ().recipient::<BindMessage>(),
                from_hopper_client: addr.clone ().recipient::<IncipientCoresPackage>(),
                from_dispatcher: addr.clone ().recipient::<InboundClientData>(),
            }
        }

        fn make_and_start_neighborhood(&self, cryptde: &'a CryptDE, config: NeighborhoodConfig) -> NeighborhoodSubs {
            self.parameters.neighborhood_params.lock ().unwrap ().get_or_insert ((cryptde, config));
            let addr: Addr<Syn, Recorder> = ActorFactoryMock::start_recorder(&self.neighborhood);
            NeighborhoodSubs {
                bind: addr.clone ().recipient::<BindMessage>(),
                bootstrap: addr.clone ().recipient::<BootstrapNeighborhoodNowMessage>(),
                node_query: addr.clone ().recipient::<NodeQueryMessage>(),
                route_query: addr.clone ().recipient::<RouteQueryMessage>(),
                from_hopper: addr.clone ().recipient::<ExpiredCoresPackage>(),
                dispatcher_node_query: addr.clone().recipient::<DispatcherNodeQueryMessage>(),
            }
        }

        fn make_and_start_stream_handler_pool(&self, _: Vec<Box<DiscriminatorFactory>>) -> StreamHandlerPoolSubs {
            let addr: Addr<Syn, Recorder> = ActorFactoryMock::start_recorder(&self.stream_handler_pool);
            StreamHandlerPoolSubs {
                add_sub: addr.clone ().recipient::<AddStreamMsg>(),
                transmit_sub: addr.clone ().recipient::<TransmitDataMsg>(),
                remove_sub: addr.clone ().recipient::<RemoveStreamMsg>(),
                bind: addr.clone ().recipient::<PoolBindMessage>(),
                node_query_response: addr.clone().recipient::<DispatcherNodeQueryResponse>(),
            }
        }

        fn make_and_start_proxy_client(&self, cryptde: &'a CryptDE, dns_servers: Vec<SocketAddr>) -> ProxyClientSubs {
            self.parameters.proxy_client_params.lock ().unwrap ().get_or_insert ((cryptde, dns_servers));
            let addr: Addr<Syn, Recorder> = ActorFactoryMock::start_recorder(&self.proxy_client);
            ProxyClientSubs {
                bind: addr.clone ().recipient::<BindMessage>(),
                from_hopper: addr.clone ().recipient::<ExpiredCoresPackage>(),
            }
        }
    }

    struct Recordings {
        dispatcher: Arc<Mutex<Recording>>,
        proxy_client: Arc<Mutex<Recording>>,
        proxy_server: Arc<Mutex<Recording>>,
        hopper: Arc<Mutex<Recording>>,
        neighborhood: Arc<Mutex<Recording>>,
        stream_handler_pool: Arc<Mutex<Recording>>,
    }

    #[derive (Clone)]
    struct Parameters<'a> {
        proxy_client_params: Arc<Mutex<Option<(&'a CryptDE, Vec<SocketAddr>)>>>,
        proxy_server_params: Arc<Mutex<Option<(&'a CryptDE, bool)>>>,
        hopper_params: Arc<Mutex<Option<(&'a CryptDE, bool)>>>,
        neighborhood_params: Arc<Mutex<Option<(&'a CryptDE, NeighborhoodConfig)>>>,
    }

    impl<'a> Parameters<'a> {
        pub fn new () -> Parameters<'a> {
            Parameters {
                proxy_client_params: Arc::new(Mutex::new(None)),
                proxy_server_params: Arc::new(Mutex::new(None)),
                hopper_params: Arc::new(Mutex::new(None)),
                neighborhood_params: Arc::new(Mutex::new(None)),
            }
        }

        pub fn get<T: Clone> (params_arc: Arc<Mutex<Option<T>>>) -> T {
            let params_opt = params_arc.lock ().unwrap ();
            params_opt.as_ref ().unwrap ().clone ()
        }
    }

    impl<'a> ActorFactoryMock<'a> {
        pub fn new () -> ActorFactoryMock<'a> {
            ActorFactoryMock {
                dispatcher: RefCell::new (Some (Recorder::new())),
                proxy_client: RefCell::new (Some (Recorder::new())),
                proxy_server: RefCell::new (Some (Recorder::new())),
                hopper: RefCell::new (Some (Recorder::new())),
                neighborhood: RefCell::new (Some (Recorder::new())),
                stream_handler_pool: RefCell::new (Some (Recorder::new())),

                parameters: Parameters::new (),
            }
        }

        pub fn get_recordings (&self) -> Recordings {
            Recordings {
                dispatcher: self.dispatcher.borrow ().as_ref ().unwrap ().get_recording (),
                proxy_client: self.proxy_client.borrow ().as_ref ().unwrap ().get_recording (),
                proxy_server: self.proxy_server.borrow ().as_ref ().unwrap ().get_recording (),
                hopper: self.hopper.borrow ().as_ref ().unwrap ().get_recording (),
                neighborhood: self.neighborhood.borrow ().as_ref ().unwrap ().get_recording (),
                stream_handler_pool: self.stream_handler_pool.borrow ().as_ref ().unwrap ().get_recording (),
            }
        }

        pub fn make_parameters (&self) -> Parameters<'a> {
            self.parameters.clone ()
        }

        fn start_recorder (recorder: &RefCell<Option<Recorder>>) -> Addr<Syn, Recorder> {
            recorder.borrow_mut ().take ().unwrap ().start ()
        }
    }

    #[test]
    fn make_and_start_actors_sends_bind_messages () {
        let actor_factory = ActorFactoryMock::new ();
        let recordings = actor_factory.get_recordings();
        let config = BootstrapperConfig {
            crash_point: CrashPoint::None,
            dns_servers: vec! (),
            neighborhood_config: NeighborhoodConfig {
                neighbor_configs: vec! (),
                bootstrap_configs: vec! (),
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                clandestine_port_list: vec! ()
            },
            clandestine_discriminator_factories: Vec::new(),
        };
        let subject = ActorSystemFactoryReal {};
        unsafe { CRYPT_DE_OPT = Some(CryptDENull::new()); }

        subject.make_and_start_actors (config, Box::new(actor_factory));

        thread::sleep (Duration::from_millis (100));
        Recording::get::<BindMessage> (&recordings.dispatcher, 0);
        Recording::get::<BindMessage> (&recordings.hopper, 0);
        Recording::get::<BindMessage> (&recordings.proxy_client, 0);
        Recording::get::<BindMessage> (&recordings.proxy_server, 0);
        Recording::get::<BindMessage> (&recordings.neighborhood, 0);
        Recording::get::<PoolBindMessage> (&recordings.stream_handler_pool, 0);
        Recording::get::<BootstrapNeighborhoodNowMessage> (&recordings.neighborhood, 1);
    }

    #[test]
    fn prepare_initial_messages_generates_the_correct_messages () {
        let actor_factory = ActorFactoryMock::new ();
        let recordings = actor_factory.get_recordings();
        let parameters = actor_factory.make_parameters ();
        let config = BootstrapperConfig {
            crash_point: CrashPoint::None,
            dns_servers: vec! (),
            neighborhood_config: NeighborhoodConfig {
                neighbor_configs: vec! (),
                bootstrap_configs: vec! (),
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                clandestine_port_list: vec! ()
            },
            clandestine_discriminator_factories: Vec::new(),
        };
        let (tx, rx) = mpsc::channel();
        let system = System::new("SubstratumNode");

        ActorSystemFactoryReal::prepare_initial_messages(cryptde (), config.clone (), Box::new (actor_factory), tx);

        Arbiter::system ().try_send (msgs::SystemExit(0)).unwrap ();
        system.run();
        check_bind_message (&recordings.dispatcher);
        check_bind_message (&recordings.hopper);
        check_bind_message (&recordings.proxy_client);
        check_bind_message (&recordings.proxy_server);
        check_bind_message (&recordings.neighborhood);
        let (cryptde, is_bootstrap_node) = Parameters::get (parameters.hopper_params);
        check_cryptde (cryptde);
        assert_eq! (is_bootstrap_node, false);
        let (cryptde, dns_servers) = Parameters::get (parameters.proxy_client_params);
        check_cryptde (cryptde);
        assert_eq! (dns_servers, config.dns_servers);
        let (actual_cryptde, actual_is_decentralized) = Parameters::get (parameters.proxy_server_params);
        check_cryptde (actual_cryptde);
        assert_eq! (actual_is_decentralized, false);
        let (cryptde, neighborhood_config) = Parameters::get (parameters.neighborhood_params);
        check_cryptde (cryptde);
        assert_eq! (neighborhood_config, config.neighborhood_config);
        let _stream_handler_pool_subs = rx.recv ().unwrap ();
        // more...more...what? How to check contents of _stream_handler_pool_subs?
    }

    fn check_bind_message (recording: &Arc<Mutex<Recording>>) {
        let bind_message = Recording::get::<BindMessage> (recording, 0);
        let _peer_actors = bind_message.peer_actors;
        // more...more...what? How to check contents of _peer_actors?
    }

    fn check_cryptde (candidate: &CryptDE) {
        let plain_data = PlainData::new (&b"booga"[..]);
        let crypt_data = candidate.encode (&candidate.public_key (), &plain_data).unwrap ();
        let result = cryptde ().decode (&cryptde ().private_key (), &crypt_data).unwrap ();
        assert_eq! (result, plain_data);
    }
}
