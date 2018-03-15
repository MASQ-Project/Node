// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use actix::Actor;
use actix::System;
use actix::SyncAddress;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::hopper::Hopper;
use stream_handler_pool::StreamHandlerPool;
use sub_lib::stream_handler_pool::StreamHandlerPoolSubs;
use dispatcher_facade::DispatcherFacade;
use proxy_server_lib::proxy_server::ProxyServer;
use sub_lib::actor_messages::BindMessage;
use sub_lib::proxy_server::ProxyServerSubs;
use sub_lib::proxy_client::ProxyClientSubs;
use sub_lib::dispatcher::DispatcherFacadeSubs;
use sub_lib::actor_messages::PeerActors;
use sub_lib::hopper::HopperSubs;
use hopper_facade::HopperFacade;
use proxy_client_lib::proxy_client::ProxyClient;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde_null::CryptDENull;
use std::net::SocketAddr;

pub trait ActorSystemFactory: Send {
    fn make_and_start_actors(&self, ibcd_transmitter: Sender<InboundClientData>, hopper: Arc<Mutex<Hopper>>, dns_servers: Vec<SocketAddr>) -> (DispatcherFacadeSubs, StreamHandlerPoolSubs);
}

pub struct ActorSystemFactoryReal {}

impl ActorSystemFactory for ActorSystemFactoryReal {
    fn make_and_start_actors(&self, ibcd_transmitter: Sender<InboundClientData>, hopper: Arc<Mutex<Hopper>>, dns_servers: Vec<SocketAddr>) -> (DispatcherFacadeSubs, StreamHandlerPoolSubs) {
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let system = System::new("SubstratumNode");

            // make all the actors
            let pool_subs = ActorSystemFactoryReal::make_and_start_stream_handler_pool();
            let dispatcher_facade_subs = ActorSystemFactoryReal::make_and_start_dispatcher_facade(ibcd_transmitter);
            let proxy_server_subs = ActorSystemFactoryReal::make_and_start_proxy_server_actor();
            let proxy_client_subs = ActorSystemFactoryReal::make_and_start_proxy_client_actor(Box::new(CryptDENull::new()), dns_servers);
            // TODO remove the next line once Hopper is actorized
            hopper.lock().expect("Hopper is Poisoned").temporary_bind(proxy_server_subs.from_hopper.clone(), proxy_client_subs.from_hopper.clone());
            let hopper_subs = ActorSystemFactoryReal::make_and_start_hopper_facade(hopper);

            // collect all the subs
            let peer_actors = PeerActors {
                proxy_server: proxy_server_subs.clone(),
                dispatcher: dispatcher_facade_subs.clone(),
                proxy_client: proxy_client_subs.clone(),
                hopper: hopper_subs.clone(),
                stream_handler_pool: pool_subs.clone(),
            };

            //bind all the actors
            dispatcher_facade_subs.bind.send(BindMessage { peer_actors: peer_actors.clone() });
            proxy_server_subs.bind.send(BindMessage { peer_actors: peer_actors.clone() });
            hopper_subs.bind.send(BindMessage { peer_actors: peer_actors.clone() });
            pool_subs.bind.send(BindMessage { peer_actors: peer_actors.clone() });
            proxy_client_subs.bind.send(BindMessage { peer_actors: peer_actors.clone() });

            tx.send((dispatcher_facade_subs.clone(), pool_subs.clone())).ok();
            system.run()
        });

        rx.recv().expect("Internal error")
    }
}

impl ActorSystemFactoryReal {
    fn make_and_start_dispatcher_facade(ibcd_transmitter: Sender<InboundClientData>) -> DispatcherFacadeSubs {
        let dispatcher_facade = DispatcherFacade::new(ibcd_transmitter);
        let addr: SyncAddress<_> = dispatcher_facade.start();
        DispatcherFacade::make_subs_from(&addr)
    }

    fn make_and_start_proxy_server_actor() -> ProxyServerSubs {
        let proxy_server = ProxyServer::new();
        let addr: SyncAddress<_> = proxy_server.start();
        ProxyServer::make_subs_from(&addr)
    }

    fn make_and_start_hopper_facade(hopper: Arc<Mutex<Hopper>>) -> HopperSubs {
        let hopper_facade = HopperFacade::new(hopper);
        let addr: SyncAddress<_> = hopper_facade.start();
        HopperFacade::make_subs_from(&addr)
    }

    fn make_and_start_stream_handler_pool() -> StreamHandlerPoolSubs {
        let pool = StreamHandlerPool::new();
        let addr: SyncAddress<_> = pool.start();
        StreamHandlerPool::make_subs_from(&addr)
    }

    fn make_and_start_proxy_client_actor(cryptde: Box<CryptDE>, dns_servers: Vec<SocketAddr>) -> ProxyClientSubs {
        let proxy_client = ProxyClient::new(cryptde, dns_servers);
        let addr: SyncAddress<_> = proxy_client.start();
        ProxyClient::make_subs_from(&addr)
    }
}