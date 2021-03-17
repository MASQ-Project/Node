// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::accountant::Accountant;
use super::bootstrapper;
use super::bootstrapper::BootstrapperConfig;
use super::discriminator::DiscriminatorFactory;
use super::dispatcher::Dispatcher;
use super::hopper::Hopper;
use super::neighborhood::Neighborhood;
use super::proxy_client::ProxyClient;
use super::proxy_server::ProxyServer;
use super::stream_handler_pool::StreamHandlerPool;
use super::stream_handler_pool::StreamHandlerPoolSubs;
use super::stream_messages::PoolBindMessage;
use super::ui_gateway::UiGateway;
use crate::banned_dao::{BannedCacheLoader, BannedCacheLoaderReal};
use crate::blockchain::blockchain_bridge::BlockchainBridge;
use crate::blockchain::blockchain_interface::{
    BlockchainInterface, BlockchainInterfaceClandestine, BlockchainInterfaceNonClandestine,
};
use crate::database::dao_utils::DaoFactoryReal;
use crate::database::db_initializer::{
    connection_or_panic, DbInitializer, DbInitializerReal, DATABASE_FILE,
};
use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::PersistentConfigurationReal;
use crate::node_configurator::configurator::Configurator;
use crate::sub_lib::accountant::AccountantSubs;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeSubs;
use crate::sub_lib::configurator::ConfiguratorSubs;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::dispatcher::DispatcherSubs;
use crate::sub_lib::hopper::HopperConfig;
use crate::sub_lib::hopper::HopperSubs;
use crate::sub_lib::neighborhood::NeighborhoodSubs;
use crate::sub_lib::peer_actors::PeerActors;
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::proxy_client::ProxyClientConfig;
use crate::sub_lib::proxy_client::ProxyClientSubs;
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
use crate::sub_lib::ui_gateway::UiGatewaySubs;
use actix::Addr;
use actix::Recipient;
use actix::{Actor, Arbiter};
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use web3::transports::Http;

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
        let main_cryptde = bootstrapper::main_cryptde_ref();
        let alias_cryptde = bootstrapper::alias_cryptde_ref();
        let (tx, rx) = mpsc::channel();

        ActorSystemFactoryReal::prepare_initial_messages(
            main_cryptde,
            alias_cryptde,
            config,
            actor_factory,
            tx,
        );

        rx.recv().expect("Internal error: actor-system init thread died before initializing StreamHandlerPool subscribers")
    }
}

impl ActorSystemFactoryReal {
    fn prepare_initial_messages(
        main_cryptde: &'static dyn CryptDE,
        alias_cryptde: &'static dyn CryptDE,
        config: BootstrapperConfig,
        actor_factory: Box<dyn ActorFactory>,
        tx: Sender<StreamHandlerPoolSubs>,
    ) {
        let db_initializer = DbInitializerReal::new();
        // make all the actors
        let (dispatcher_subs, pool_bind_sub) = actor_factory.make_and_start_dispatcher(&config);
        let proxy_server_subs = actor_factory.make_and_start_proxy_server(
            main_cryptde,
            alias_cryptde,
            config.neighborhood_config.mode.is_decentralized(),
            if config.consuming_wallet.is_none() {
                None
            } else {
                Some(0)
            },
        );
        let proxy_client_subs = if !config.neighborhood_config.mode.is_consume_only() {
            Some(
                actor_factory.make_and_start_proxy_client(ProxyClientConfig {
                    cryptde: main_cryptde,
                    dns_servers: config.dns_servers.clone(),
                    exit_service_rate: config
                        .neighborhood_config
                        .mode
                        .rate_pack()
                        .clone()
                        .exit_service_rate,
                    exit_byte_rate: config.neighborhood_config.mode.rate_pack().exit_byte_rate,
                }),
            )
        } else {
            None
        };

        let hopper_subs = actor_factory.make_and_start_hopper(HopperConfig {
            main_cryptde,
            alias_cryptde,
            per_routing_service: config
                .neighborhood_config
                .mode
                .rate_pack()
                .clone()
                .routing_service_rate,
            per_routing_byte: config
                .neighborhood_config
                .mode
                .rate_pack()
                .clone()
                .routing_byte_rate,
            is_decentralized: config.neighborhood_config.mode.is_decentralized(),
        });
        let blockchain_bridge_subs =
            actor_factory.make_and_start_blockchain_bridge(&config, &db_initializer);
        let neighborhood_subs = actor_factory.make_and_start_neighborhood(main_cryptde, &config);
        let accountant_subs = actor_factory.make_and_start_accountant(
            &config,
            &config.data_directory.clone(),
            &db_initializer,
            &BannedCacheLoaderReal {},
        );
        let ui_gateway_subs =
            actor_factory.make_and_start_ui_gateway(config.ui_gateway_config.clone());
        let stream_handler_pool_subs = actor_factory
            .make_and_start_stream_handler_pool(config.clandestine_discriminator_factories.clone());
        let configurator_subs = actor_factory.make_and_start_configurator(&config);

        // collect all the subs
        let peer_actors = PeerActors {
            dispatcher: dispatcher_subs.clone(),
            proxy_server: proxy_server_subs,
            proxy_client_opt: proxy_client_subs.clone(),
            hopper: hopper_subs,
            neighborhood: neighborhood_subs.clone(),
            accountant: accountant_subs,
            ui_gateway: ui_gateway_subs,
            blockchain_bridge: blockchain_bridge_subs,
            configurator: configurator_subs,
        };

        //bind all the actors
        send_bind_message!(peer_actors.dispatcher, peer_actors);
        send_bind_message!(peer_actors.proxy_server, peer_actors);
        send_bind_message!(peer_actors.hopper, peer_actors);
        send_bind_message!(peer_actors.neighborhood, peer_actors);
        send_bind_message!(peer_actors.accountant, peer_actors);
        send_bind_message!(peer_actors.ui_gateway, peer_actors);
        send_bind_message!(peer_actors.blockchain_bridge, peer_actors);
        send_bind_message!(peer_actors.configurator, peer_actors);
        if let Some(subs) = proxy_client_subs {
            send_bind_message!(subs, peer_actors);
        }
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
                neighborhood_subs,
            })
            .expect("Dispatcher is dead");

        //after we've bound all the actors, send start messages to any actors that need it
        send_start_message!(peer_actors.neighborhood);

        //send out the stream handler pool subs (to be bound to listeners)
        tx.send(stream_handler_pool_subs).ok();
    }
}

pub trait ActorFactory: Send {
    fn make_and_start_dispatcher(
        &self,
        config: &BootstrapperConfig,
    ) -> (DispatcherSubs, Recipient<PoolBindMessage>);
    fn make_and_start_proxy_server(
        &self,
        main_cryptde: &'static dyn CryptDE,
        alias_cryptde: &'static dyn CryptDE,
        is_decentralized: bool,
        consuming_wallet_balance: Option<i64>,
    ) -> ProxyServerSubs;
    fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs;
    fn make_and_start_neighborhood(
        &self,
        cryptde: &'static dyn CryptDE,
        config: &BootstrapperConfig,
    ) -> NeighborhoodSubs;
    fn make_and_start_accountant(
        &self,
        config: &BootstrapperConfig,
        data_directory: &PathBuf,
        db_initializer: &dyn DbInitializer,
        banned_cache_loader: &dyn BannedCacheLoader,
    ) -> AccountantSubs;
    fn make_and_start_ui_gateway(&self, config: UiGatewayConfig) -> UiGatewaySubs;
    fn make_and_start_stream_handler_pool(
        &self,
        clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    ) -> StreamHandlerPoolSubs;
    fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs;
    fn make_and_start_blockchain_bridge(
        &self,
        config: &BootstrapperConfig,
        db_initializer: &dyn DbInitializer,
    ) -> BlockchainBridgeSubs;
    fn make_and_start_configurator(&self, config: &BootstrapperConfig) -> ConfiguratorSubs;
}

pub struct ActorFactoryReal {}

impl ActorFactory for ActorFactoryReal {
    fn make_and_start_dispatcher(
        &self,
        config: &BootstrapperConfig,
    ) -> (DispatcherSubs, Recipient<PoolBindMessage>) {
        let crash_point = config.crash_point;
        let descriptor = config.ui_gateway_config.node_descriptor.clone();
        let addr: Addr<Dispatcher> =
            Arbiter::start(move |_| Dispatcher::new(crash_point, descriptor));
        (
            Dispatcher::make_subs_from(&addr),
            addr.recipient::<PoolBindMessage>(),
        )
    }

    fn make_and_start_proxy_server(
        &self,
        main_cryptde: &'static dyn CryptDE,
        alias_cryptde: &'static dyn CryptDE,
        is_decentralized: bool,
        consuming_wallet_balance: Option<i64>,
    ) -> ProxyServerSubs {
        let addr: Addr<ProxyServer> = Arbiter::start(move |_| {
            ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                is_decentralized,
                consuming_wallet_balance,
            )
        });
        ProxyServer::make_subs_from(&addr)
    }

    fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs {
        let addr: Addr<Hopper> = Arbiter::start(|_| Hopper::new(config));
        Hopper::make_subs_from(&addr)
    }

    fn make_and_start_neighborhood(
        &self,
        cryptde: &'static dyn CryptDE,
        config: &BootstrapperConfig,
    ) -> NeighborhoodSubs {
        let config_clone = config.clone();
        let addr: Addr<Neighborhood> =
            Arbiter::start(move |_| Neighborhood::new(cryptde, &config_clone));
        Neighborhood::make_subs_from(&addr)
    }

    fn make_and_start_accountant(
        &self,
        config: &BootstrapperConfig,
        data_directory: &PathBuf,
        db_initializer: &dyn DbInitializer,
        banned_cache_loader: &dyn BannedCacheLoader,
    ) -> AccountantSubs {
        let cloned_config = config.clone();
        let chain_id = config.blockchain_bridge_config.chain_id;
        let payable_dao_factory = DaoFactoryReal::new(
            data_directory,
            config.blockchain_bridge_config.chain_id,
            false,
        );
        let receivable_dao_factory = DaoFactoryReal::new(
            data_directory,
            config.blockchain_bridge_config.chain_id,
            false,
        );
        let banned_dao_factory = DaoFactoryReal::new(
            data_directory,
            config.blockchain_bridge_config.chain_id,
            false,
        );
        banned_cache_loader.load(connection_or_panic(
            db_initializer,
            data_directory,
            chain_id,
            false,
        ));
        let config_dao_factory = DaoFactoryReal::new(
            data_directory,
            config.blockchain_bridge_config.chain_id,
            false,
        );
        let addr: Addr<Accountant> = Arbiter::start(move |_| {
            Accountant::new(
                &cloned_config,
                Box::new(payable_dao_factory),
                Box::new(receivable_dao_factory),
                Box::new(banned_dao_factory),
                Box::new(config_dao_factory),
            )
        });
        Accountant::make_subs_from(&addr)
    }

    fn make_and_start_ui_gateway(&self, config: UiGatewayConfig) -> UiGatewaySubs {
        let ui_gateway = UiGateway::new(&config);
        let addr: Addr<UiGateway> = Arbiter::start(|_| ui_gateway);
        UiGateway::make_subs_from(&addr)
    }

    fn make_and_start_stream_handler_pool(
        &self,
        clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    ) -> StreamHandlerPoolSubs {
        let addr: Addr<StreamHandlerPool> =
            Arbiter::start(|_| StreamHandlerPool::new(clandestine_discriminator_factories));
        StreamHandlerPool::make_subs_from(&addr)
    }

    fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs {
        let addr: Addr<ProxyClient> = Arbiter::start(|_| ProxyClient::new(config));
        ProxyClient::make_subs_from(&addr)
    }

    fn make_and_start_blockchain_bridge(
        &self,
        config: &BootstrapperConfig,
        db_initializer: &dyn DbInitializer,
    ) -> BlockchainBridgeSubs {
        let blockchain_service_url = config
            .blockchain_bridge_config
            .blockchain_service_url
            .clone();
        let blockchain_interface: Box<dyn BlockchainInterface> = {
            match blockchain_service_url {
                Some(url) => match Http::new(&url) {
                    Ok((event_loop_handle, transport)) => {
                        Box::new(BlockchainInterfaceNonClandestine::new(
                            transport,
                            event_loop_handle,
                            config.blockchain_bridge_config.chain_id,
                        ))
                    }
                    Err(e) => panic!("Invalid blockchain node URL: {:?}", e),
                },
                None => Box::new(BlockchainInterfaceClandestine::new(
                    config.blockchain_bridge_config.chain_id,
                )),
            }
        };
        let config_dao = Box::new(ConfigDaoReal::new(
            db_initializer
                .initialize(
                    &config.data_directory,
                    config.blockchain_bridge_config.chain_id,
                    true,
                )
                .unwrap_or_else(|_| {
                    panic!(
                        "Failed to connect to database at {:?}",
                        &config.data_directory.join(DATABASE_FILE)
                    )
                }),
        ));
        let persistent_config = Box::new(PersistentConfigurationReal::new(config_dao));
        let blockchain_bridge =
            BlockchainBridge::new(config, blockchain_interface, persistent_config);
        let addr: Addr<BlockchainBridge> = blockchain_bridge.start();
        BlockchainBridge::make_subs_from(&addr)
    }

    fn make_and_start_configurator(&self, config: &BootstrapperConfig) -> ConfiguratorSubs {
        let configurator = Configurator::new(
            config.data_directory.clone(),
            config.blockchain_bridge_config.chain_id,
        );
        let addr: Addr<Configurator> = configurator.start();
        ConfiguratorSubs {
            bind: recipient!(addr, BindMessage),
            node_from_ui_sub: recipient!(addr, NodeFromUiMessage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::{ReceivedPayments, SentPayments};
    use crate::blockchain::blockchain_bridge::RetrieveTransactions;
    use crate::bootstrapper::{Bootstrapper, RealUser};
    use crate::database::connection_wrapper::ConnectionWrapper;
    use crate::database::db_initializer::test_utils::DbInitializerMock;
    use crate::neighborhood::gossip::Gossip_0v1;
    use crate::stream_messages::AddStreamMsg;
    use crate::stream_messages::RemoveStreamMsg;
    use crate::sub_lib::accountant::AccountantConfig;
    use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
    use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
    use crate::sub_lib::accountant::{
        ReportExitServiceConsumedMessage, ReportExitServiceProvidedMessage,
    };
    use crate::sub_lib::blockchain_bridge::{BlockchainBridgeConfig, ReportAccountsPayable};
    use crate::sub_lib::configurator::NewPasswordMessage;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::dispatcher::{InboundClientData, StreamShutdownMsg};
    use crate::sub_lib::hopper::IncipientCoresPackage;
    use crate::sub_lib::hopper::{ExpiredCoresPackage, NoLookupIncipientCoresPackage};
    use crate::sub_lib::neighborhood::RouteQueryMessage;
    use crate::sub_lib::neighborhood::{
        DispatcherNodeQueryMessage, GossipFailure_0v1, NodeRecordMetadataMessage,
    };
    use crate::sub_lib::neighborhood::{NeighborhoodConfig, NodeQueryMessage};
    use crate::sub_lib::neighborhood::{NeighborhoodMode, RemoveNeighborMessage};
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::peer_actors::StartMessage;
    use crate::sub_lib::proxy_client::{
        ClientResponsePayload_0v1, DnsResolveFailure_0v1, InboundServerData,
    };
    use crate::sub_lib::proxy_server::{
        AddReturnRouteMessage, AddRouteMessage, ClientRequestPayload_0v1,
    };
    use crate::sub_lib::set_consuming_wallet_message::SetConsumingWalletMessage;
    use crate::sub_lib::stream_handler_pool::DispatcherNodeQueryResponse;
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use crate::sub_lib::ui_gateway::UiGatewayConfig;
    use crate::test_utils::recorder::Recorder;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::{alias_cryptde, rate_pack};
    use crate::test_utils::{main_cryptde, make_wallet};
    use actix::System;
    use log::LevelFilter;
    use masq_lib::crash_point::CrashPoint;
    use masq_lib::test_utils::utils::DEFAULT_CHAIN_ID;
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use masq_lib::ui_gateway::NodeToUiMessage;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    #[derive(Default)]
    struct BannedCacheLoaderMock {
        pub load_params: Arc<Mutex<Vec<Box<dyn ConnectionWrapper>>>>,
    }

    impl BannedCacheLoader for BannedCacheLoaderMock {
        fn load(&self, conn: Box<dyn ConnectionWrapper>) {
            self.load_params.lock().unwrap().push(conn);
        }
    }

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
        configurator: RefCell<Option<Recorder>>,

        parameters: Parameters<'a>,
    }

    impl<'a> ActorFactory for ActorFactoryMock<'a> {
        fn make_and_start_dispatcher(
            &self,
            _config: &BootstrapperConfig,
        ) -> (DispatcherSubs, Recipient<PoolBindMessage>) {
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.dispatcher);
            let dispatcher_subs = DispatcherSubs {
                ibcd_sub: recipient!(addr, InboundClientData),
                bind: recipient!(addr, BindMessage),
                from_dispatcher_client: recipient!(addr, TransmitDataMsg),
                stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
                ui_sub: recipient!(addr, NodeFromUiMessage),
            };
            (dispatcher_subs, addr.recipient::<PoolBindMessage>())
        }

        fn make_and_start_proxy_server(
            &self,
            main_cryptde: &'a dyn CryptDE,
            alias_cryptde: &'a dyn CryptDE,
            is_decentralized: bool,
            consuming_wallet_balance: Option<i64>,
        ) -> ProxyServerSubs {
            self.parameters
                .proxy_server_params
                .lock()
                .unwrap()
                .get_or_insert((
                    main_cryptde,
                    alias_cryptde,
                    is_decentralized,
                    consuming_wallet_balance,
                ));
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.proxy_server);
            ProxyServerSubs {
                bind: recipient!(addr, BindMessage),
                from_dispatcher: recipient!(addr, InboundClientData),
                from_hopper: addr
                    .clone()
                    .recipient::<ExpiredCoresPackage<ClientResponsePayload_0v1>>(),
                dns_failure_from_hopper: addr
                    .clone()
                    .recipient::<ExpiredCoresPackage<DnsResolveFailure_0v1>>(),
                add_return_route: recipient!(addr, AddReturnRouteMessage),
                add_route: recipient!(addr, AddRouteMessage),
                stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
                set_consuming_wallet_sub: recipient!(addr, SetConsumingWalletMessage),
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
                bind: recipient!(addr, BindMessage),
                from_hopper_client: recipient!(addr, IncipientCoresPackage),
                from_hopper_client_no_lookup: addr
                    .clone()
                    .recipient::<NoLookupIncipientCoresPackage>(),
                from_dispatcher: recipient!(addr, InboundClientData),
            }
        }

        fn make_and_start_neighborhood(
            &self,
            cryptde: &'a dyn CryptDE,
            config: &BootstrapperConfig,
        ) -> NeighborhoodSubs {
            self.parameters
                .neighborhood_params
                .lock()
                .unwrap()
                .get_or_insert((cryptde, config.clone()));
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.neighborhood);
            NeighborhoodSubs {
                bind: recipient!(addr, BindMessage),
                start: recipient!(addr, StartMessage),
                node_query: recipient!(addr, NodeQueryMessage),
                route_query: recipient!(addr, RouteQueryMessage),
                update_node_record_metadata: recipient!(addr, NodeRecordMetadataMessage),
                from_hopper: addr.clone().recipient::<ExpiredCoresPackage<Gossip_0v1>>(),
                gossip_failure: addr
                    .clone()
                    .recipient::<ExpiredCoresPackage<GossipFailure_0v1>>(),
                dispatcher_node_query: recipient!(addr, DispatcherNodeQueryMessage),
                remove_neighbor: recipient!(addr, RemoveNeighborMessage),
                stream_shutdown_sub: recipient!(addr, StreamShutdownMsg),
                set_consuming_wallet_sub: recipient!(addr, SetConsumingWalletMessage),
                from_ui_message_sub: addr.clone().recipient::<NodeFromUiMessage>(),
                new_password_sub: addr.clone().recipient::<NewPasswordMessage>(),
            }
        }

        fn make_and_start_accountant(
            &self,
            config: &BootstrapperConfig,
            data_directory: &PathBuf,
            _db_initializer: &dyn DbInitializer,
            _banned_cache_loader: &dyn BannedCacheLoader,
        ) -> AccountantSubs {
            self.parameters
                .accountant_params
                .lock()
                .unwrap()
                .get_or_insert((config.clone(), data_directory.clone()));
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.accountant);
            AccountantSubs {
                bind: recipient!(addr, BindMessage),
                start: recipient!(addr, StartMessage),
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
                report_new_payments: recipient!(addr, ReceivedPayments),
                report_sent_payments: recipient!(addr, SentPayments),
                ui_message_sub: addr.clone().recipient::<NodeFromUiMessage>(),
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
                bind: recipient!(addr, BindMessage),
                node_from_ui_message_sub: recipient!(addr, NodeFromUiMessage),
                node_to_ui_message_sub: recipient!(addr, NodeToUiMessage),
            }
        }

        fn make_and_start_stream_handler_pool(
            &self,
            _: Vec<Box<dyn DiscriminatorFactory>>,
        ) -> StreamHandlerPoolSubs {
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.stream_handler_pool);
            StreamHandlerPoolSubs {
                add_sub: recipient!(addr, AddStreamMsg),
                transmit_sub: recipient!(addr, TransmitDataMsg),
                remove_sub: recipient!(addr, RemoveStreamMsg),
                bind: recipient!(addr, PoolBindMessage),
                node_query_response: recipient!(addr, DispatcherNodeQueryResponse),
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
                bind: recipient!(addr, BindMessage),
                from_hopper: addr
                    .clone()
                    .recipient::<ExpiredCoresPackage<ClientRequestPayload_0v1>>(),
                inbound_server_data: recipient!(addr, InboundServerData),
                dns_resolve_failed: recipient!(addr, DnsResolveFailure_0v1),
            }
        }

        fn make_and_start_blockchain_bridge(
            &self,
            config: &BootstrapperConfig,
            _db_initializer: &dyn DbInitializer,
        ) -> BlockchainBridgeSubs {
            self.parameters
                .blockchain_bridge_params
                .lock()
                .unwrap()
                .get_or_insert(config.clone());
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.blockchain_bridge);
            BlockchainBridgeSubs {
                bind: recipient!(addr, BindMessage),
                report_accounts_payable: addr.clone().recipient::<ReportAccountsPayable>(),
                retrieve_transactions: addr.clone().recipient::<RetrieveTransactions>(),
                ui_sub: addr.clone().recipient::<NodeFromUiMessage>(),
            }
        }

        fn make_and_start_configurator(&self, config: &BootstrapperConfig) -> ConfiguratorSubs {
            self.parameters
                .configurator_params
                .lock()
                .unwrap()
                .get_or_insert(config.clone());
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.configurator);
            ConfiguratorSubs {
                bind: recipient!(addr, BindMessage),
                node_from_ui_sub: recipient!(addr, NodeFromUiMessage),
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
        configurator: Arc<Mutex<Recording>>,
    }

    #[derive(Clone)]
    struct Parameters<'a> {
        proxy_client_params: Arc<Mutex<Option<ProxyClientConfig>>>,
        proxy_server_params:
            Arc<Mutex<Option<(&'a dyn CryptDE, &'a dyn CryptDE, bool, Option<i64>)>>>,
        hopper_params: Arc<Mutex<Option<HopperConfig>>>,
        neighborhood_params: Arc<Mutex<Option<(&'a dyn CryptDE, BootstrapperConfig)>>>,
        accountant_params: Arc<Mutex<Option<(BootstrapperConfig, PathBuf)>>>,
        ui_gateway_params: Arc<Mutex<Option<UiGatewayConfig>>>,
        blockchain_bridge_params: Arc<Mutex<Option<BootstrapperConfig>>>,
        configurator_params: Arc<Mutex<Option<BootstrapperConfig>>>,
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
                configurator_params: Arc::new(Mutex::new(None)),
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
                configurator: RefCell::new(Some(Recorder::new())),

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
                configurator: self.configurator.borrow().as_ref().unwrap().get_recording(),
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
    #[should_panic(expected = "Invalid blockchain node URL")]
    fn invalid_blockchain_url_produces_panic() {
        let bbconfig = BlockchainBridgeConfig {
            blockchain_service_url: Some("http://λ:8545".to_string()),
            chain_id: DEFAULT_CHAIN_ID,
            gas_price: 1,
        };
        let mut config = BootstrapperConfig::new();
        config.blockchain_bridge_config = bbconfig;
        config.consuming_wallet = None;
        let subject = ActorFactoryReal {};
        subject.make_and_start_blockchain_bridge(&config, &DbInitializerMock::new());
    }

    #[test]
    fn make_and_start_actors_sends_bind_messages() {
        let actor_factory = ActorFactoryMock::new();
        let recordings = actor_factory.get_recordings();
        let config = BootstrapperConfig {
            log_level: LevelFilter::Off,
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            accountant_config: AccountantConfig {
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
            },
            clandestine_discriminator_factories: Vec::new(),
            ui_gateway_config: UiGatewayConfig {
                ui_port: 5335,
                node_descriptor: String::from("uninitialized"),
            },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url: None,
                chain_id: DEFAULT_CHAIN_ID,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), &[]),
                    vec![],
                    rate_pack(100),
                ),
            },
        };
        Bootstrapper::pub_initialize_cryptdes_for_testing(
            &Some(main_cryptde().clone()),
            &Some(alias_cryptde().clone()),
        );
        let subject = ActorSystemFactoryReal {};

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
        Recording::get::<BindMessage>(&recordings.configurator, 0);
        Recording::get::<PoolBindMessage>(&recordings.stream_handler_pool, 0);
        Recording::get::<StartMessage>(&recordings.neighborhood, 1);
    }

    #[test]
    fn prepare_initial_messages_generates_the_correct_messages() {
        let actor_factory = ActorFactoryMock::new();
        let recordings = actor_factory.get_recordings();
        let parameters = actor_factory.make_parameters();
        let config = BootstrapperConfig {
            log_level: LevelFilter::Off,
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            accountant_config: AccountantConfig {
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
            },
            clandestine_discriminator_factories: Vec::new(),
            ui_gateway_config: UiGatewayConfig {
                ui_port: 5335,
                node_descriptor: String::from("NODE-DESCRIPTOR"),
            },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url: None,
                chain_id: DEFAULT_CHAIN_ID,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::ZeroHop,
            },
        };
        let (tx, rx) = mpsc::channel();
        let system = System::new("MASQNode");

        ActorSystemFactoryReal::prepare_initial_messages(
            main_cryptde(),
            alias_cryptde(),
            config.clone(),
            Box::new(actor_factory),
            tx,
        );

        System::current().stop();
        system.run();
        check_bind_message(&recordings.dispatcher, false);
        check_bind_message(&recordings.hopper, false);
        check_bind_message(&recordings.proxy_client, false);
        check_bind_message(&recordings.proxy_server, false);
        check_bind_message(&recordings.neighborhood, false);
        check_bind_message(&recordings.ui_gateway, false);
        check_bind_message(&recordings.accountant, false);
        check_start_message(&recordings.neighborhood);
        let hopper_config = Parameters::get(parameters.hopper_params);
        check_cryptde(hopper_config.main_cryptde);
        assert_eq!(hopper_config.per_routing_service, 0);
        assert_eq!(hopper_config.per_routing_byte, 0);
        let proxy_client_config = Parameters::get(parameters.proxy_client_params);
        check_cryptde(proxy_client_config.cryptde);
        assert_eq!(proxy_client_config.exit_service_rate, 0);
        assert_eq!(proxy_client_config.exit_byte_rate, 0);
        assert_eq!(proxy_client_config.dns_servers, config.dns_servers);
        let (
            actual_main_cryptde,
            actual_alias_cryptde,
            actual_is_decentralized,
            consuming_wallet_balance,
        ) = Parameters::get(parameters.proxy_server_params);
        check_cryptde(actual_main_cryptde);
        check_cryptde(actual_alias_cryptde);
        assert_ne!(
            actual_main_cryptde.public_key(),
            actual_alias_cryptde.public_key()
        );
        assert_eq!(actual_is_decentralized, false);
        assert_eq!(consuming_wallet_balance, Some(0));
        let (cryptde, neighborhood_config) = Parameters::get(parameters.neighborhood_params);
        check_cryptde(cryptde);
        assert_eq!(
            neighborhood_config.neighborhood_config,
            config.neighborhood_config
        );
        assert_eq!(
            neighborhood_config.consuming_wallet,
            config.consuming_wallet
        );
        let ui_gateway_config = Parameters::get(parameters.ui_gateway_params);
        assert_eq!(ui_gateway_config.ui_port, 5335);
        assert_eq!(ui_gateway_config.node_descriptor, "NODE-DESCRIPTOR");
        let bootstrapper_config = Parameters::get(parameters.blockchain_bridge_params);
        assert_eq!(
            bootstrapper_config.blockchain_bridge_config,
            BlockchainBridgeConfig {
                blockchain_service_url: None,
                chain_id: DEFAULT_CHAIN_ID,
                gas_price: 1,
            }
        );
        assert_eq!(
            bootstrapper_config.consuming_wallet,
            Some(make_wallet("consuming"))
        );
        let _stream_handler_pool_subs = rx.recv().unwrap();
        // more...more...what? How to check contents of _stream_handler_pool_subs?
    }

    #[test]
    fn prepare_initial_messages_doesnt_start_up_proxy_client_if_consume_only_mode() {
        let actor_factory = ActorFactoryMock::new();
        let recordings = actor_factory.get_recordings();
        let config = BootstrapperConfig {
            log_level: LevelFilter::Off,
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            accountant_config: AccountantConfig {
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
            },
            clandestine_discriminator_factories: Vec::new(),
            ui_gateway_config: UiGatewayConfig {
                ui_port: 5335,
                node_descriptor: String::from("NODE-DESCRIPTOR"),
            },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url: None,
                chain_id: DEFAULT_CHAIN_ID,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::ConsumeOnly(vec![]),
            },
        };
        let system = System::new("MASQNode");

        ActorSystemFactoryReal::prepare_initial_messages(
            main_cryptde(),
            alias_cryptde(),
            config.clone(),
            Box::new(actor_factory),
            mpsc::channel().0,
        );

        System::current().stop();
        system.run();

        let messages = recordings.proxy_client.lock().unwrap();
        assert!(messages.is_empty());
        check_bind_message(&recordings.dispatcher, true);
        check_bind_message(&recordings.hopper, true);
        check_bind_message(&recordings.proxy_server, true);
        check_bind_message(&recordings.neighborhood, true);
        check_bind_message(&recordings.ui_gateway, true);
        check_bind_message(&recordings.accountant, true);
        check_start_message(&recordings.neighborhood);
    }

    #[test]
    fn prepare_initial_messages_generates_no_consuming_wallet_balance_if_no_consuming_wallet_is_specified(
    ) {
        let actor_factory = ActorFactoryMock::new();
        let parameters = actor_factory.make_parameters();
        let config = BootstrapperConfig {
            log_level: LevelFilter::Off,
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            accountant_config: AccountantConfig {
                payable_scan_interval: Duration::from_secs(100),
                payment_received_scan_interval: Duration::from_secs(100),
            },
            clandestine_discriminator_factories: Vec::new(),
            ui_gateway_config: UiGatewayConfig {
                ui_port: 5335,
                node_descriptor: String::from("NODE-DESCRIPTOR"),
            },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url: None,
                chain_id: DEFAULT_CHAIN_ID,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet: None,
            data_directory: PathBuf::new(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), &[]),
                    vec![],
                    rate_pack(100),
                ),
            },
        };
        let (tx, _) = mpsc::channel();
        let system = System::new("MASQNode");

        ActorSystemFactoryReal::prepare_initial_messages(
            main_cryptde(),
            alias_cryptde(),
            config.clone(),
            Box::new(actor_factory),
            tx,
        );

        System::current().stop();
        system.run();
        let (_, _, _, consuming_wallet_balance) = Parameters::get(parameters.proxy_server_params);
        assert_eq!(consuming_wallet_balance, None);
    }

    fn check_bind_message(recording: &Arc<Mutex<Recording>>, consume_only_flag: bool) {
        let bind_message = Recording::get::<BindMessage>(recording, 0);
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.neighborhood),
            "NeighborhoodSubs"
        );
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.accountant),
            "AccountantSubs"
        );
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.ui_gateway),
            "UiGatewaySubs"
        );
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.blockchain_bridge),
            "BlockchainBridgeSubs"
        );
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.dispatcher),
            "DispatcherSubs"
        );
        assert_eq!(
            format!("{:?}", bind_message.peer_actors.hopper),
            "HopperSubs"
        );

        assert_eq!(
            format!("{:?}", bind_message.peer_actors.proxy_server),
            "ProxyServerSubs"
        );

        if consume_only_flag {
            assert!(bind_message.peer_actors.proxy_client_opt.is_none())
        } else {
            assert_eq!(
                format!("{:?}", bind_message.peer_actors.proxy_client_opt.unwrap()),
                "ProxyClientSubs"
            )
        };
    }

    fn check_start_message(recording: &Arc<Mutex<Recording>>) {
        let _start_message = Recording::get::<StartMessage>(recording, 1);
    }

    fn check_cryptde(candidate: &dyn CryptDE) {
        let plain_data = PlainData::new(&b"booga"[..]);
        let crypt_data = candidate
            .encode(&candidate.public_key(), &plain_data)
            .unwrap();
        let result = candidate.decode(&crypt_data).unwrap();
        assert_eq!(result, plain_data);
    }
}
