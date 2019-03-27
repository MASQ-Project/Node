// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::accountant::accountant::Accountant;
use super::bootstrapper;
use super::bootstrapper::BootstrapperConfig;
use super::discriminator::DiscriminatorFactory;
use super::dispatcher::Dispatcher;
use super::hopper::hopper::Hopper;
use super::neighborhood::neighborhood::Neighborhood;
use super::proxy_client::proxy_client::ProxyClient;
use super::proxy_server::proxy_server::ProxyServer;
use super::stream_handler_pool::StreamHandlerPool;
use super::stream_handler_pool::StreamHandlerPoolSubs;
use super::stream_messages::PoolBindMessage;
use super::ui_gateway::ui_gateway::UiGateway;
use crate::blockchain_bridge::blockchain_bridge::BlockchainBridge;
use crate::sub_lib::accountant::AccountantConfig;
use crate::sub_lib::accountant::AccountantSubs;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::dispatcher::DispatcherSubs;
use crate::sub_lib::hopper::HopperConfig;
use crate::sub_lib::hopper::HopperSubs;
use crate::sub_lib::neighborhood::BootstrapNeighborhoodNowMessage;
use crate::sub_lib::neighborhood::NeighborhoodConfig;
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::peer_actors::PeerActors;
use crate::sub_lib::proxy_client::ProxyClientConfig;
use crate::sub_lib::proxy_client::ProxyClientSubs;
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
use crate::sub_lib::ui_gateway::UiGatewaySubs;
use actix::Actor;
use actix::Addr;
use actix::Recipient;
use std::sync::mpsc;
use std::sync::mpsc::Sender;

pub trait ActorSystemFactory: Send {
    fn make_and_start_actors(
        &self,
        config: BootstrapperConfig,
        actor_factory: Box<dyn ActorFactory>,
    ) -> StreamHandlerPoolSubs;
}

pub struct ActorSystemFactoryReal {}

impl ActorSystemFactory for ActorSystemFactoryReal {
    fn make_and_start_actors(
        &self,
        config: BootstrapperConfig,
        actor_factory: Box<dyn ActorFactory>,
    ) -> StreamHandlerPoolSubs {
        let cryptde: &'static CryptDENull =
            unsafe { bootstrapper::CRYPT_DE_OPT.as_ref().expect("Internal error") };
        let (tx, rx) = mpsc::channel();

        ActorSystemFactoryReal::prepare_initial_messages(cryptde, config, actor_factory, tx);

        rx.recv().expect("Internal error: actor-system init thread died before initializing StreamHandlerPool subscribers")
    }
}

impl ActorSystemFactoryReal {
    fn prepare_initial_messages(
        cryptde: &'static dyn CryptDE,
        config: BootstrapperConfig,
        actor_factory: Box<dyn ActorFactory>,
        tx: Sender<StreamHandlerPoolSubs>,
    ) {
        // make all the actors
        let (dispatcher_subs, pool_bind_sub) = actor_factory.make_and_start_dispatcher();
        let proxy_server_subs = actor_factory
            .make_and_start_proxy_server(cryptde, config.neighborhood_config.is_decentralized());
        let proxy_client_subs = actor_factory.make_and_start_proxy_client(ProxyClientConfig {
            cryptde,
            dns_servers: config.dns_servers,
            exit_service_rate: config.neighborhood_config.rate_pack.exit_service_rate,
            exit_byte_rate: config.neighborhood_config.rate_pack.exit_byte_rate,
        });
        let hopper_subs = actor_factory.make_and_start_hopper(HopperConfig {
            cryptde,
            is_bootstrap_node: config.neighborhood_config.is_bootstrap_node,
            per_routing_service: config.neighborhood_config.rate_pack.routing_service_rate,
            per_routing_byte: config.neighborhood_config.rate_pack.routing_byte_rate,
        });
        let neighborhood_subs =
            actor_factory.make_and_start_neighborhood(cryptde, config.neighborhood_config);
        let accountant_subs = actor_factory.make_and_start_accountant(config.accountant_config);
        let ui_gateway_subs = actor_factory.make_and_start_ui_gateway(config.ui_gateway_config);
        let stream_handler_pool_subs = actor_factory
            .make_and_start_stream_handler_pool(config.clandestine_discriminator_factories);
        let blockchain_bridge_subs =
            actor_factory.make_and_start_blockchain_bridge(config.blockchain_bridge_config);

        // collect all the subs
        let peer_actors = PeerActors {
            dispatcher: dispatcher_subs.clone(),
            proxy_server: proxy_server_subs,
            proxy_client: proxy_client_subs,
            hopper: hopper_subs,
            neighborhood: neighborhood_subs.clone(),
            accountant: accountant_subs.clone(),
            ui_gateway: ui_gateway_subs.clone(),
            blockchain_bridge: blockchain_bridge_subs.clone(),
        };

        //bind all the actors
        peer_actors
            .dispatcher
            .bind
            .try_send(BindMessage {
                peer_actors: peer_actors.clone(),
            })
            .expect("Dispatcher is dead");
        peer_actors
            .proxy_server
            .bind
            .try_send(BindMessage {
                peer_actors: peer_actors.clone(),
            })
            .expect("Proxy Server is dead");
        peer_actors
            .proxy_client
            .bind
            .try_send(BindMessage {
                peer_actors: peer_actors.clone(),
            })
            .expect("Proxy Client is dead");
        peer_actors
            .hopper
            .bind
            .try_send(BindMessage {
                peer_actors: peer_actors.clone(),
            })
            .expect("Hopper is dead");
        peer_actors
            .neighborhood
            .bind
            .try_send(BindMessage {
                peer_actors: peer_actors.clone(),
            })
            .expect("Neighborhood is dead");
        peer_actors
            .accountant
            .bind
            .try_send(BindMessage {
                peer_actors: peer_actors.clone(),
            })
            .expect("Accountant is dead");
        peer_actors
            .ui_gateway
            .bind
            .try_send(BindMessage {
                peer_actors: peer_actors.clone(),
            })
            .expect("UiGateway is dead");
        peer_actors
            .blockchain_bridge
            .bind
            .try_send(BindMessage {
                peer_actors: peer_actors.clone(),
            })
            .expect("BlockchainBridge is dead");
        stream_handler_pool_subs
            .bind
            .try_send(PoolBindMessage {
                dispatcher_subs: dispatcher_subs.clone(),
                stream_handler_pool_subs: stream_handler_pool_subs.clone(),
                neighborhood_subs: neighborhood_subs.clone(),
            })
            .expect("Stream Handler Pool is dead");
        pool_bind_sub
            .try_send(PoolBindMessage {
                dispatcher_subs,
                stream_handler_pool_subs: stream_handler_pool_subs.clone(),
                neighborhood_subs: neighborhood_subs.clone(),
            })
            .expect("Dispatcher is dead");
        peer_actors
            .neighborhood
            .bootstrap
            .try_send(BootstrapNeighborhoodNowMessage {})
            .expect("Neighborhood is dead");

        //send out the stream handler pool subs (to be bound to listeners)
        tx.send(stream_handler_pool_subs).ok();
    }
}

pub trait ActorFactory: Send {
    fn make_and_start_dispatcher(&self) -> (DispatcherSubs, Recipient<PoolBindMessage>);
    fn make_and_start_proxy_server(
        &self,
        cryptde: &'static dyn CryptDE,
        is_decentralized: bool,
    ) -> ProxyServerSubs;
    fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs;
    fn make_and_start_neighborhood(
        &self,
        cryptde: &'static dyn CryptDE,
        config: NeighborhoodConfig,
    ) -> NeighborhoodSubs;
    fn make_and_start_accountant(&self, config: AccountantConfig) -> AccountantSubs;
    fn make_and_start_ui_gateway(&self, config: UiGatewayConfig) -> UiGatewaySubs;
    fn make_and_start_stream_handler_pool(
        &self,
        clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    ) -> StreamHandlerPoolSubs;
    fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs;
    fn make_and_start_blockchain_bridge(
        &self,
        config: BlockchainBridgeConfig,
    ) -> BlockchainBridgeSubs;
}

pub struct ActorFactoryReal {}

impl ActorFactory for ActorFactoryReal {
    fn make_and_start_dispatcher(&self) -> (DispatcherSubs, Recipient<PoolBindMessage>) {
        let dispatcher = Dispatcher::new();
        let addr: Addr<Dispatcher> = dispatcher.start();
        (
            Dispatcher::make_subs_from(&addr),
            addr.recipient::<PoolBindMessage>(),
        )
    }

    fn make_and_start_proxy_server(
        &self,
        cryptde: &'static dyn CryptDE,
        is_decentralized: bool,
    ) -> ProxyServerSubs {
        let proxy_server = ProxyServer::new(cryptde, is_decentralized);
        let addr: Addr<ProxyServer> = proxy_server.start();
        ProxyServer::make_subs_from(&addr)
    }

    fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs {
        let hopper = Hopper::new(config);
        let addr: Addr<Hopper> = hopper.start();
        Hopper::make_subs_from(&addr)
    }

    fn make_and_start_neighborhood(
        &self,
        cryptde: &'static dyn CryptDE,
        config: NeighborhoodConfig,
    ) -> NeighborhoodSubs {
        let neighborhood = Neighborhood::new(cryptde, config);
        let addr: Addr<Neighborhood> = neighborhood.start();
        Neighborhood::make_subs_from(&addr)
    }

    fn make_and_start_accountant(&self, config: AccountantConfig) -> AccountantSubs {
        let accountant = Accountant::new(config);
        let addr: Addr<Accountant> = accountant.start();
        Accountant::make_subs_from(&addr)
    }

    fn make_and_start_ui_gateway(&self, config: UiGatewayConfig) -> UiGatewaySubs {
        let ui_gateway = UiGateway::new(&config);
        let addr: Addr<UiGateway> = ui_gateway.start();
        UiGateway::make_subs_from(&addr)
    }

    fn make_and_start_stream_handler_pool(
        &self,
        clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    ) -> StreamHandlerPoolSubs {
        let pool = StreamHandlerPool::new(clandestine_discriminator_factories);
        let addr: Addr<StreamHandlerPool> = pool.start();
        StreamHandlerPool::make_subs_from(&addr)
    }

    fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs {
        let proxy_client = ProxyClient::new(config);
        let addr: Addr<ProxyClient> = proxy_client.start();
        ProxyClient::make_subs_from(&addr)
    }

    fn make_and_start_blockchain_bridge(
        &self,
        config: BlockchainBridgeConfig,
    ) -> BlockchainBridgeSubs {
        let blockchain_bridge = BlockchainBridge::new(config);
        let addr: Addr<BlockchainBridge> = blockchain_bridge.start();
        BlockchainBridge::make_subs_from(&addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrapper::CRYPT_DE_OPT;
    use crate::neighborhood::gossip::Gossip;
    use crate::stream_messages::AddStreamMsg;
    use crate::stream_messages::RemoveStreamMsg;
    use crate::sub_lib::accountant::ReportExitServiceConsumedMessage;
    use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
    use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
    use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::sub_lib::crash_point::CrashPoint;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::dispatcher::InboundClientData;
    use crate::sub_lib::hopper::ExpiredCoresPackage;
    use crate::sub_lib::hopper::IncipientCoresPackage;
    use crate::sub_lib::neighborhood::DispatcherNodeQueryMessage;
    use crate::sub_lib::neighborhood::NodeQueryMessage;
    use crate::sub_lib::neighborhood::RemoveNeighborMessage;
    use crate::sub_lib::neighborhood::RouteQueryMessage;
    use crate::sub_lib::proxy_client::{ClientResponsePayload, InboundServerData};
    use crate::sub_lib::proxy_server::{AddReturnRouteMessage, ClientRequestPayload};
    use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use crate::sub_lib::ui_gateway::UiGatewayConfig;
    use crate::sub_lib::ui_gateway::{FromUiMessage, UiCarrierMessage};
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::test_utils::cryptde;
    use crate::test_utils::test_utils::rate_pack;
    use crate::test_utils::test_utils::rate_pack_exit;
    use crate::test_utils::test_utils::rate_pack_exit_byte;
    use crate::test_utils::test_utils::rate_pack_routing;
    use crate::test_utils::test_utils::rate_pack_routing_byte;
    use actix::System;
    use std::cell::RefCell;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    struct ActorFactoryMock<'a> {
        dispatcher: RefCell<Option<Recorder>>,
        proxy_client: RefCell<Option<Recorder>>,
        proxy_server: RefCell<Option<Recorder>>,
        hopper: RefCell<Option<Recorder>>,
        neighborhood: RefCell<Option<Recorder>>,
        accountant: RefCell<Option<Recorder>>,
        stream_handler_pool: RefCell<Option<Recorder>>,
        ui_gateway: RefCell<Option<Recorder>>,
        blockchain_bridge: RefCell<Option<Recorder>>,

        parameters: Parameters<'a>,
    }

    impl<'a> ActorFactory for ActorFactoryMock<'a> {
        fn make_and_start_dispatcher(&self) -> (DispatcherSubs, Recipient<PoolBindMessage>) {
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.dispatcher);
            let dispatcher_subs = DispatcherSubs {
                ibcd_sub: addr.clone().recipient::<InboundClientData>(),
                bind: addr.clone().recipient::<BindMessage>(),
                from_dispatcher_client: addr.clone().recipient::<TransmitDataMsg>(),
            };
            (dispatcher_subs, addr.recipient::<PoolBindMessage>())
        }

        fn make_and_start_proxy_server(
            &self,
            cryptde: &'a dyn CryptDE,
            is_decentralized: bool,
        ) -> ProxyServerSubs {
            self.parameters
                .proxy_server_params
                .lock()
                .unwrap()
                .get_or_insert((cryptde, is_decentralized));
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.proxy_server);
            ProxyServerSubs {
                bind: addr.clone().recipient::<BindMessage>(),
                from_dispatcher: addr.clone().recipient::<InboundClientData>(),
                from_hopper: addr
                    .clone()
                    .recipient::<ExpiredCoresPackage<ClientResponsePayload>>(),
                add_return_route: addr.clone().recipient::<AddReturnRouteMessage>(),
            }
        }

        fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs {
            self.parameters
                .hopper_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.hopper);
            HopperSubs {
                bind: addr.clone().recipient::<BindMessage>(),
                from_hopper_client: addr.clone().recipient::<IncipientCoresPackage>(),
                from_dispatcher: addr.clone().recipient::<InboundClientData>(),
            }
        }

        fn make_and_start_neighborhood(
            &self,
            cryptde: &'a dyn CryptDE,
            config: NeighborhoodConfig,
        ) -> NeighborhoodSubs {
            self.parameters
                .neighborhood_params
                .lock()
                .unwrap()
                .get_or_insert((cryptde, config));
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.neighborhood);
            NeighborhoodSubs {
                bind: addr.clone().recipient::<BindMessage>(),
                bootstrap: addr.clone().recipient::<BootstrapNeighborhoodNowMessage>(),
                node_query: addr.clone().recipient::<NodeQueryMessage>(),
                route_query: addr.clone().recipient::<RouteQueryMessage>(),
                from_hopper: addr.clone().recipient::<ExpiredCoresPackage<Gossip>>(),
                dispatcher_node_query: addr.clone().recipient::<DispatcherNodeQueryMessage>(),
                remove_neighbor: addr.clone().recipient::<RemoveNeighborMessage>(),
            }
        }

        fn make_and_start_accountant(&self, config: AccountantConfig) -> AccountantSubs {
            self.parameters
                .accountant_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.accountant);
            AccountantSubs {
                bind: addr.clone().recipient::<BindMessage>(),
                report_routing_service_provided: addr
                    .clone()
                    .recipient::<ReportRoutingServiceProvidedMessage>(),
                report_exit_service_provided: addr
                    .clone()
                    .recipient::<ReportExitServiceProvidedMessage>(),
                report_routing_service_consumed: addr
                    .clone()
                    .recipient::<ReportRoutingServiceConsumedMessage>(),
                report_exit_service_consumed: addr
                    .clone()
                    .recipient::<ReportExitServiceConsumedMessage>(),
            }
        }

        fn make_and_start_ui_gateway(&self, config: UiGatewayConfig) -> UiGatewaySubs {
            self.parameters
                .ui_gateway_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.ui_gateway);
            UiGatewaySubs {
                bind: addr.clone().recipient::<BindMessage>(),
                ui_message_sub: addr.clone().recipient::<UiCarrierMessage>(),
                from_ui_message_sub: addr.clone().recipient::<FromUiMessage>(),
            }
        }

        fn make_and_start_stream_handler_pool(
            &self,
            _: Vec<Box<dyn DiscriminatorFactory>>,
        ) -> StreamHandlerPoolSubs {
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.stream_handler_pool);
            StreamHandlerPoolSubs {
                add_sub: addr.clone().recipient::<AddStreamMsg>(),
                transmit_sub: addr.clone().recipient::<TransmitDataMsg>(),
                remove_sub: addr.clone().recipient::<RemoveStreamMsg>(),
                bind: addr.clone().recipient::<PoolBindMessage>(),
                node_query_response: addr.clone().recipient::<DispatcherNodeQueryResponse>(),
            }
        }

        fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs {
            self.parameters
                .proxy_client_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.proxy_client);
            ProxyClientSubs {
                bind: addr.clone().recipient::<BindMessage>(),
                from_hopper: addr
                    .clone()
                    .recipient::<ExpiredCoresPackage<ClientRequestPayload>>(),
                inbound_server_data: addr.clone().recipient::<InboundServerData>(),
            }
        }

        fn make_and_start_blockchain_bridge(
            &self,
            config: BlockchainBridgeConfig,
        ) -> BlockchainBridgeSubs {
            self.parameters
                .blockchain_bridge_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.blockchain_bridge);
            BlockchainBridgeSubs {
                bind: addr.clone().recipient::<BindMessage>(),
                report_accounts_payable: addr.clone().recipient::<ReportAccountsPayable>(),
            }
        }
    }

    struct Recordings {
        dispatcher: Arc<Mutex<Recording>>,
        proxy_client: Arc<Mutex<Recording>>,
        proxy_server: Arc<Mutex<Recording>>,
        hopper: Arc<Mutex<Recording>>,
        neighborhood: Arc<Mutex<Recording>>,
        accountant: Arc<Mutex<Recording>>,
        stream_handler_pool: Arc<Mutex<Recording>>,
        ui_gateway: Arc<Mutex<Recording>>,
        blockchain_bridge: Arc<Mutex<Recording>>,
    }

    #[derive(Clone)]
    struct Parameters<'a> {
        proxy_client_params: Arc<Mutex<Option<(ProxyClientConfig)>>>,
        proxy_server_params: Arc<Mutex<Option<(&'a dyn CryptDE, bool)>>>,
        hopper_params: Arc<Mutex<Option<HopperConfig>>>,
        neighborhood_params: Arc<Mutex<Option<(&'a dyn CryptDE, NeighborhoodConfig)>>>,
        accountant_params: Arc<Mutex<Option<AccountantConfig>>>,
        ui_gateway_params: Arc<Mutex<Option<UiGatewayConfig>>>,
        blockchain_bridge_params: Arc<Mutex<Option<BlockchainBridgeConfig>>>,
    }

    impl<'a> Parameters<'a> {
        pub fn new() -> Parameters<'a> {
            Parameters {
                proxy_client_params: Arc::new(Mutex::new(None)),
                proxy_server_params: Arc::new(Mutex::new(None)),
                hopper_params: Arc::new(Mutex::new(None)),
                neighborhood_params: Arc::new(Mutex::new(None)),
                accountant_params: Arc::new(Mutex::new(None)),
                ui_gateway_params: Arc::new(Mutex::new(None)),
                blockchain_bridge_params: Arc::new(Mutex::new(None)),
            }
        }

        pub fn get<T: Clone>(params_arc: Arc<Mutex<Option<T>>>) -> T {
            let params_opt = params_arc.lock().unwrap();
            params_opt.as_ref().unwrap().clone()
        }
    }

    impl<'a> ActorFactoryMock<'a> {
        pub fn new() -> ActorFactoryMock<'a> {
            ActorFactoryMock {
                dispatcher: RefCell::new(Some(Recorder::new())),
                proxy_client: RefCell::new(Some(Recorder::new())),
                proxy_server: RefCell::new(Some(Recorder::new())),
                hopper: RefCell::new(Some(Recorder::new())),
                neighborhood: RefCell::new(Some(Recorder::new())),
                accountant: RefCell::new(Some(Recorder::new())),
                stream_handler_pool: RefCell::new(Some(Recorder::new())),
                ui_gateway: RefCell::new(Some(Recorder::new())),
                blockchain_bridge: RefCell::new(Some(Recorder::new())),

                parameters: Parameters::new(),
            }
        }

        pub fn get_recordings(&self) -> Recordings {
            Recordings {
                dispatcher: self.dispatcher.borrow().as_ref().unwrap().get_recording(),
                proxy_client: self.proxy_client.borrow().as_ref().unwrap().get_recording(),
                proxy_server: self.proxy_server.borrow().as_ref().unwrap().get_recording(),
                hopper: self.hopper.borrow().as_ref().unwrap().get_recording(),
                neighborhood: self.neighborhood.borrow().as_ref().unwrap().get_recording(),
                accountant: self.accountant.borrow().as_ref().unwrap().get_recording(),
                stream_handler_pool: self
                    .stream_handler_pool
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .get_recording(),
                ui_gateway: self.ui_gateway.borrow().as_ref().unwrap().get_recording(),
                blockchain_bridge: self
                    .blockchain_bridge
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .get_recording(),
            }
        }

        pub fn make_parameters(&self) -> Parameters<'a> {
            self.parameters.clone()
        }

        fn start_recorder(recorder: &RefCell<Option<Recorder>>) -> Addr<Recorder> {
            recorder.borrow_mut().take().unwrap().start()
        }
    }

    #[test]
    fn make_and_start_actors_sends_bind_messages() {
        let actor_factory = ActorFactoryMock::new();
        let recordings = actor_factory.get_recordings();
        let config = BootstrapperConfig {
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            neighborhood_config: NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                clandestine_port_list: vec![],
                earning_wallet: Wallet::new("router"),
                consuming_wallet: Some(Wallet::new("consumer")),
                rate_pack: rate_pack(100),
            },
            accountant_config: AccountantConfig {
                data_directory: PathBuf::new(),
                payable_scan_interval: Duration::from_secs(100),
            },
            clandestine_discriminator_factories: Vec::new(),
            ui_gateway_config: UiGatewayConfig {
                ui_port: 5335,
                node_descriptor: String::from(""),
            },
            blockchain_bridge_config: BlockchainBridgeConfig {
                consuming_private_key: None,
            },
        };
        let subject = ActorSystemFactoryReal {};
        unsafe {
            CRYPT_DE_OPT = Some(CryptDENull::new());
        }

        let system = System::new("test");
        subject.make_and_start_actors(config, Box::new(actor_factory));
        System::current().stop();
        system.run();

        thread::sleep(Duration::from_millis(100));
        Recording::get::<BindMessage>(&recordings.dispatcher, 0);
        Recording::get::<BindMessage>(&recordings.hopper, 0);
        Recording::get::<BindMessage>(&recordings.proxy_client, 0);
        Recording::get::<BindMessage>(&recordings.proxy_server, 0);
        Recording::get::<BindMessage>(&recordings.neighborhood, 0);
        Recording::get::<BindMessage>(&recordings.accountant, 0);
        Recording::get::<BindMessage>(&recordings.ui_gateway, 0);
        Recording::get::<BindMessage>(&recordings.blockchain_bridge, 0);
        Recording::get::<PoolBindMessage>(&recordings.stream_handler_pool, 0);
        Recording::get::<BootstrapNeighborhoodNowMessage>(&recordings.neighborhood, 1);
    }

    #[test]
    fn prepare_initial_messages_generates_the_correct_messages() {
        let actor_factory = ActorFactoryMock::new();
        let recordings = actor_factory.get_recordings();
        let parameters = actor_factory.make_parameters();
        let config = BootstrapperConfig {
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            neighborhood_config: NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                clandestine_port_list: vec![],
                earning_wallet: Wallet::new("router"),
                consuming_wallet: Some(Wallet::new("consumer")),
                rate_pack: rate_pack(100),
            },
            accountant_config: AccountantConfig {
                data_directory: PathBuf::new(),
                payable_scan_interval: Duration::from_secs(100),
            },
            clandestine_discriminator_factories: Vec::new(),
            ui_gateway_config: UiGatewayConfig {
                ui_port: 5335,
                node_descriptor: String::from("NODE-DESCRIPTOR"),
            },
            blockchain_bridge_config: BlockchainBridgeConfig {
                consuming_private_key: None,
            },
        };
        let (tx, rx) = mpsc::channel();
        let system = System::new("SubstratumNode");

        ActorSystemFactoryReal::prepare_initial_messages(
            cryptde(),
            config.clone(),
            Box::new(actor_factory),
            tx,
        );

        System::current().stop_with_code(0);
        system.run();
        check_bind_message(&recordings.dispatcher);
        check_bind_message(&recordings.hopper);
        check_bind_message(&recordings.proxy_client);
        check_bind_message(&recordings.proxy_server);
        check_bind_message(&recordings.neighborhood);
        check_bind_message(&recordings.ui_gateway);
        let hopper_config = Parameters::get(parameters.hopper_params);
        check_cryptde(hopper_config.cryptde);
        assert_eq!(hopper_config.is_bootstrap_node, false);
        assert_eq!(hopper_config.per_routing_service, rate_pack_routing(100));
        assert_eq!(hopper_config.per_routing_byte, rate_pack_routing_byte(100));
        let proxy_client_config = Parameters::get(parameters.proxy_client_params);
        check_cryptde(proxy_client_config.cryptde);
        assert_eq!(proxy_client_config.exit_service_rate, rate_pack_exit(100),);
        assert_eq!(proxy_client_config.exit_byte_rate, rate_pack_exit_byte(100),);
        assert_eq!(proxy_client_config.dns_servers, config.dns_servers);
        let (actual_cryptde, actual_is_decentralized) =
            Parameters::get(parameters.proxy_server_params);
        check_cryptde(actual_cryptde);
        assert_eq!(actual_is_decentralized, false);
        let (cryptde, neighborhood_config) = Parameters::get(parameters.neighborhood_params);
        check_cryptde(cryptde);
        assert_eq!(neighborhood_config, config.neighborhood_config);
        let ui_gateway_config = Parameters::get(parameters.ui_gateway_params);
        assert_eq!(ui_gateway_config.ui_port, 5335);
        assert_eq!(ui_gateway_config.node_descriptor, "NODE-DESCRIPTOR");
        let blockchain_bridge_config = Parameters::get(parameters.blockchain_bridge_params);
        assert_eq!(
            blockchain_bridge_config,
            BlockchainBridgeConfig {
                consuming_private_key: None
            }
        );
        let _stream_handler_pool_subs = rx.recv().unwrap();
        // more...more...what? How to check contents of _stream_handler_pool_subs?
    }

    fn check_bind_message(recording: &Arc<Mutex<Recording>>) {
        let bind_message = Recording::get::<BindMessage>(recording, 0);
        let _peer_actors = bind_message.peer_actors;
        // more...more...what? How to check contents of _peer_actors?
    }

    fn check_cryptde(candidate: &dyn CryptDE) {
        let plain_data = PlainData::new(&b"booga"[..]);
        let crypt_data = candidate
            .encode(&candidate.public_key(), &plain_data)
            .unwrap();
        let result = cryptde().decode(&crypt_data).unwrap();
        assert_eq!(result, plain_data);
    }
}
