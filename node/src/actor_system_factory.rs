// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;
use actix::Actor;
use actix::System;
use actix::SyncAddress;
use hopper_lib::hopper::Hopper;
use proxy_client_lib::proxy_client::ProxyClient;
use proxy_server_lib::proxy_server::ProxyServer;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::hopper::HopperSubs;
use sub_lib::dispatcher::DispatcherSubs;
use sub_lib::peer_actors::BindMessage;
use sub_lib::peer_actors::PeerActors;
use sub_lib::proxy_client::ProxyClientSubs;
use sub_lib::proxy_server::ProxyServerSubs;
use dispatcher::Dispatcher;
use stream_handler_pool::StreamHandlerPool;
use stream_handler_pool::StreamHandlerPoolSubs;
use stream_handler_pool::PoolBindMessage;
use actix::Subscriber;

pub trait ActorSystemFactory: Send {
    fn make_and_start_actors(&self, dns_servers: Vec<SocketAddr>) -> StreamHandlerPoolSubs;
}

pub struct ActorSystemFactoryReal {}

impl ActorSystemFactory for ActorSystemFactoryReal {
    // THIS CODE HAS NO UNIT TESTS
    fn make_and_start_actors(&self, dns_servers: Vec<SocketAddr>) -> StreamHandlerPoolSubs {
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let system = System::new("SubstratumNode");

            // make all the actors
            let (dispatcher_subs, pool_bind_sub) = ActorSystemFactoryReal::make_and_start_dispatcher();
            let proxy_server_subs = ActorSystemFactoryReal::make_and_start_proxy_server();
            let proxy_client_subs = ActorSystemFactoryReal::make_and_start_proxy_client(Box::new(CryptDENull::new()), dns_servers);
            let hopper_subs = ActorSystemFactoryReal::make_and_start_hopper(Box::new(CryptDENull::new()));
            //let neighborhood_subs = ActorSystemFactoryReal::make_and_start_neighborhood();
            let stream_handler_pool_subs = ActorSystemFactoryReal::make_and_start_stream_handler_pool();

            // collect all the subs
            let peer_actors = PeerActors {
                dispatcher: dispatcher_subs.clone (),
                proxy_server: proxy_server_subs,
                proxy_client: proxy_client_subs,
                hopper: hopper_subs,
                // neighborhood: neighborhood_subs
            };

            //bind all the actors
            peer_actors.dispatcher.bind.send(BindMessage { peer_actors: peer_actors.clone() }).expect ("Dispatcher is dead");
            peer_actors.proxy_server.bind.send(BindMessage { peer_actors: peer_actors.clone() }).expect ("Proxy Server is dead");
            peer_actors.proxy_client.bind.send(BindMessage { peer_actors: peer_actors.clone() }).expect ("Proxy Client is dead");
            peer_actors.hopper.bind.send(BindMessage { peer_actors: peer_actors.clone() }).expect ("Hopper is dead");
            //peer_actors.neighborhood.bind.send(BindMessage { peer_actors: peer_actors.clone() }).expect("Neighborhood is dead");
            stream_handler_pool_subs.bind.send(PoolBindMessage {dispatcher_subs: dispatcher_subs.clone (), stream_handler_pool_subs: stream_handler_pool_subs.clone ()}).expect ("Stream Handler Pool is dead");
            pool_bind_sub.send (PoolBindMessage {dispatcher_subs, stream_handler_pool_subs: stream_handler_pool_subs.clone ()}).expect ("Dispatcher is dead");

            //send out the stream handler pool subs (to be bound to listeners)
            tx.send(stream_handler_pool_subs).ok();

            //run the actor system
            system.run()
        });

        rx.recv().expect("Internal error")
    }
}

impl ActorSystemFactoryReal {
    fn make_and_start_dispatcher() -> (DispatcherSubs, Box<Subscriber<PoolBindMessage>>) {
        let dispatcher = Dispatcher::new();
        let addr: SyncAddress<_> = dispatcher.start();
        (Dispatcher::make_subs_from(&addr), addr.subscriber::<PoolBindMessage> ())
    }

    fn make_and_start_proxy_server() -> ProxyServerSubs {
        let proxy_server = ProxyServer::new();
        let addr: SyncAddress<_> = proxy_server.start();
        ProxyServer::make_subs_from(&addr)
    }

    fn make_and_start_hopper(cryptde: Box<CryptDE>) -> HopperSubs {
        let hopper = Hopper::new(cryptde);
        let addr: SyncAddress<_> = hopper.start();
        Hopper::make_subs_from(&addr)
    }

    fn make_and_start_stream_handler_pool() -> StreamHandlerPoolSubs {
        let pool = StreamHandlerPool::new();
        let addr: SyncAddress<_> = pool.start();
        StreamHandlerPool::make_subs_from(&addr)
    }

    fn make_and_start_proxy_client(cryptde: Box<CryptDE>, dns_servers: Vec<SocketAddr>) -> ProxyClientSubs {
        let proxy_client = ProxyClient::new(cryptde, dns_servers);
        let addr: SyncAddress<_> = proxy_client.start();
        ProxyClient::make_subs_from(&addr)
    }
}