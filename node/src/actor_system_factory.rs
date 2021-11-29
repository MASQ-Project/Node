// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use super::accountant::Accountant;
use super::bootstrapper;
use super::bootstrapper::BootstrapperConfig;
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
use crate::database::db_initializer::{connection_or_panic, DbInitializer, DbInitializerReal};
use crate::database::db_migrations::MigratorConfig;
use crate::db_config::persistent_configuration::PersistentConfiguration;
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
use crate::sub_lib::ui_gateway::UiGatewaySubs;
use actix::Addr;
use actix::Arbiter;
use actix::Recipient;
use masq_lib::blockchains::chains::Chain;
use masq_lib::crash_point::CrashPoint;
use masq_lib::ui_gateway::NodeFromUiMessage;
use masq_lib::utils::ExpectValue;
use std::path::Path;

pub trait ActorSystemFactory: Send {
    fn make_and_start_actors(
        &self,
        config: BootstrapperConfig,
        actor_factory: Box<dyn ActorFactory>,
        persist_config: &dyn PersistentConfiguration,
        actor_system_factory_tools: &dyn ActorSystemFactoryTools,
    ) -> StreamHandlerPoolSubs;
}

pub trait ActorSystemFactoryTools {
    fn prepare_initial_messages(
        &self,
        main_cryptde: &'static dyn CryptDE,
        alias_cryptde: &'static dyn CryptDE,
        config: BootstrapperConfig,
        actor_factory: Box<dyn ActorFactory>,
    ) -> StreamHandlerPoolSubs;
    fn main_cryptde_ref(&self) -> &'static dyn CryptDE;
    fn alias_cryptde_ref(&self) -> &'static dyn CryptDE;
    fn database_chain_assertion(
        &self,
        chain: Chain,
        persistent_config: &dyn PersistentConfiguration,
    );
}

pub struct ActorSystemFactoryReal {}

impl ActorSystemFactory for ActorSystemFactoryReal {
    fn make_and_start_actors(
        &self,
        config: BootstrapperConfig,
        actor_factory: Box<dyn ActorFactory>,
        persist_config: &dyn PersistentConfiguration,
        tools: &dyn ActorSystemFactoryTools,
    ) -> StreamHandlerPoolSubs {
        let main_cryptde = tools.main_cryptde_ref();
        let alias_cryptde = tools.alias_cryptde_ref();
        tools.database_chain_assertion(config.blockchain_bridge_config.chain, persist_config);

        tools.prepare_initial_messages(main_cryptde, alias_cryptde, config, actor_factory)
    }
}

pub struct ActorSystemFactoryToolsReal;

impl ActorSystemFactoryTools for ActorSystemFactoryToolsReal {
    fn prepare_initial_messages(
        &self,
        main_cryptde: &'static dyn CryptDE,
        alias_cryptde: &'static dyn CryptDE,
        config: BootstrapperConfig,
        actor_factory: Box<dyn ActorFactory>,
    ) -> StreamHandlerPoolSubs {
        let db_initializer = DbInitializerReal::default();
        // make all the actors
        let (dispatcher_subs, pool_bind_sub) = actor_factory.make_and_start_dispatcher(&config);
        let proxy_server_subs =
            actor_factory.make_and_start_proxy_server(main_cryptde, alias_cryptde, &config);
        let proxy_client_subs_opt = if !config.neighborhood_config.mode.is_consume_only() {
            Some(
                actor_factory.make_and_start_proxy_client(ProxyClientConfig {
                    cryptde: main_cryptde,
                    dns_servers: config.dns_servers.clone(),
                    exit_service_rate: config.exit_service_rate(),
                    exit_byte_rate: config.exit_byte_rate(),
                    crashable: ActorFactoryReal::is_crashable(&config),
                }),
            )
        } else {
            None
        };
        let hopper_subs = actor_factory.make_and_start_hopper(HopperConfig {
            main_cryptde,
            alias_cryptde,
            per_routing_service: config.routing_service_rate(),
            per_routing_byte: config.routing_byte_rate(),
            is_decentralized: config.neighborhood_config.mode.is_decentralized(),
            crashable: ActorFactoryReal::is_crashable(&config),
        });
        let blockchain_bridge_subs = actor_factory.make_and_start_blockchain_bridge(&config);
        let neighborhood_subs = actor_factory.make_and_start_neighborhood(main_cryptde, &config);
        let accountant_subs = actor_factory.make_and_start_accountant(
            &config,
            &config.data_directory.clone(),
            &db_initializer,
            &BannedCacheLoaderReal {},
        );
        let ui_gateway_subs = actor_factory.make_and_start_ui_gateway(&config);
        let stream_handler_pool_subs = actor_factory.make_and_start_stream_handler_pool(&config);
        let configurator_subs = actor_factory.make_and_start_configurator(&config);

        // collect all the subs
        let peer_actors = PeerActors {
            dispatcher: dispatcher_subs.clone(),
            proxy_server: proxy_server_subs,
            proxy_client_opt: proxy_client_subs_opt.clone(),
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
        if let Some(subs) = proxy_client_subs_opt {
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
        stream_handler_pool_subs
    }

    fn main_cryptde_ref(&self) -> &'static dyn CryptDE {
        bootstrapper::main_cryptde_ref()
    }

    fn alias_cryptde_ref(&self) -> &'static dyn CryptDE {
        bootstrapper::alias_cryptde_ref()
    }

    fn database_chain_assertion(
        &self,
        chain: Chain,
        persistent_config: &dyn PersistentConfiguration,
    ) {
        let requested_chain = chain.rec().literal_identifier.to_string();
        let chain_in_db = persistent_config.chain_name();
        if requested_chain != chain_in_db {
            panic!(
                "Database with the wrong chain name detected; expected: {}, was: {}",
                requested_chain, chain_in_db
            )
        }
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
        config: &BootstrapperConfig,
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
        data_directory: &Path,
        db_initializer: &dyn DbInitializer,
        banned_cache_loader: &dyn BannedCacheLoader,
    ) -> AccountantSubs;
    fn make_and_start_ui_gateway(&self, config: &BootstrapperConfig) -> UiGatewaySubs;
    fn make_and_start_stream_handler_pool(
        &self,
        config: &BootstrapperConfig,
    ) -> StreamHandlerPoolSubs;
    fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs;
    fn make_and_start_blockchain_bridge(&self, config: &BootstrapperConfig)
        -> BlockchainBridgeSubs;
    fn make_and_start_configurator(&self, config: &BootstrapperConfig) -> ConfiguratorSubs;
}

pub struct ActorFactoryReal {}

impl ActorFactory for ActorFactoryReal {
    fn make_and_start_dispatcher(
        &self,
        config: &BootstrapperConfig,
    ) -> (DispatcherSubs, Recipient<PoolBindMessage>) {
        let descriptor = config.node_descriptor_opt.clone();
        let crashable = Self::is_crashable(config);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Dispatcher> = arbiter
            .start(move |_| Dispatcher::new(descriptor.expectv("node descriptor"), crashable));
        (
            Dispatcher::make_subs_from(&addr),
            addr.recipient::<PoolBindMessage>(),
        )
    }

    fn make_and_start_proxy_server(
        &self,
        main_cryptde: &'static dyn CryptDE,
        alias_cryptde: &'static dyn CryptDE,
        config: &BootstrapperConfig,
    ) -> ProxyServerSubs {
        let is_decentralized = config.neighborhood_config.mode.is_decentralized();
        let consuming_wallet_balance = if config.consuming_wallet.is_some() {
            Some(0)
        } else {
            None
        };
        let crashable = Self::is_crashable(config);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<ProxyServer> = arbiter.start(move |_| {
            ProxyServer::new(
                main_cryptde,
                alias_cryptde,
                is_decentralized,
                consuming_wallet_balance,
                crashable,
            )
        });
        ProxyServer::make_subs_from(&addr)
    }

    fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs {
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Hopper> = arbiter.start(move |_| Hopper::new(config));
        Hopper::make_subs_from(&addr)
    }

    fn make_and_start_neighborhood(
        &self,
        cryptde: &'static dyn CryptDE,
        config: &BootstrapperConfig,
    ) -> NeighborhoodSubs {
        let config_clone = config.clone();
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Neighborhood> =
            arbiter.start(move |_| Neighborhood::new(cryptde, &config_clone));
        Neighborhood::make_subs_from(&addr)
    }

    fn make_and_start_accountant(
        &self,
        config: &BootstrapperConfig,
        data_directory: &Path,
        db_initializer: &dyn DbInitializer,
        banned_cache_loader: &dyn BannedCacheLoader,
    ) -> AccountantSubs {
        let cloned_config = config.clone();
        let payable_dao_factory = Accountant::dao_factory(data_directory);
        let receivable_dao_factory = Accountant::dao_factory(data_directory);
        let banned_dao_factory = Accountant::dao_factory(data_directory);
        banned_cache_loader.load(connection_or_panic(
            db_initializer,
            data_directory,
            false,
            MigratorConfig::panic_on_migration(),
        ));
        let config_dao_factory = Accountant::dao_factory(data_directory);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Accountant> = arbiter.start(move |_| {
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

    fn make_and_start_ui_gateway(&self, config: &BootstrapperConfig) -> UiGatewaySubs {
        let crashable = Self::is_crashable(config);
        let ui_gateway = UiGateway::new(&config.ui_gateway_config, crashable);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<UiGateway> = arbiter.start(move |_| ui_gateway);
        UiGateway::make_subs_from(&addr)
    }

    fn make_and_start_stream_handler_pool(
        &self,
        config: &BootstrapperConfig,
    ) -> StreamHandlerPoolSubs {
        let clandestine_discriminator_factories =
            config.clandestine_discriminator_factories.clone();
        let crashable = Self::is_crashable(config);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<StreamHandlerPool> = arbiter
            .start(move |_| StreamHandlerPool::new(clandestine_discriminator_factories, crashable));
        StreamHandlerPool::make_subs_from(&addr)
    }

    fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs {
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<ProxyClient> = arbiter.start(move |_| ProxyClient::new(config));
        ProxyClient::make_subs_from(&addr)
    }

    fn make_and_start_blockchain_bridge(
        &self,
        config: &BootstrapperConfig,
    ) -> BlockchainBridgeSubs {
        let blockchain_service_url_opt = config
            .blockchain_bridge_config
            .blockchain_service_url_opt
            .clone();
        let crashable = Self::is_crashable(config);
        let wallet_opt = config.consuming_wallet.clone();
        let data_directory = config.data_directory.clone();
        let chain_id = config.blockchain_bridge_config.chain;
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<BlockchainBridge> = arbiter.start(move |_| {
            let (blockchain_interface, persistent_config) = BlockchainBridge::make_connections(
                blockchain_service_url_opt,
                &DbInitializerReal::default(),
                data_directory,
                chain_id,
            );
            BlockchainBridge::new(
                blockchain_interface,
                persistent_config,
                crashable,
                wallet_opt,
            )
        });
        BlockchainBridge::make_subs_from(&addr)
    }

    fn make_and_start_configurator(&self, config: &BootstrapperConfig) -> ConfiguratorSubs {
        let data_directory = config.data_directory.clone();
        let crashable = Self::is_crashable(config);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Configurator> =
            arbiter.start(move |_| Configurator::new(data_directory, crashable));
        ConfiguratorSubs {
            bind: recipient!(addr, BindMessage),
            node_from_ui_sub: recipient!(addr, NodeFromUiMessage),
        }
    }
}

impl ActorFactoryReal {
    fn is_crashable(config: &BootstrapperConfig) -> bool {
        config.crash_point == CrashPoint::Message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::{ReceivedPayments, SentPayments};
    use crate::blockchain::blockchain_bridge::RetrieveTransactions;
    use crate::bootstrapper::{Bootstrapper, RealUser};
    use crate::database::connection_wrapper::ConnectionWrapper;
    use crate::neighborhood::gossip::Gossip_0v1;
    use crate::node_test_utils::{
        make_stream_handler_pool_subs_from, make_stream_handler_pool_subs_from_an_addr,
        start_recorder_refcell_opt,
    };
    use crate::sub_lib::accountant::AccountantConfig;
    use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
    use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
    use crate::sub_lib::accountant::{
        ReportExitServiceConsumedMessage, ReportExitServiceProvidedMessage,
    };
    use crate::sub_lib::blockchain_bridge::{BlockchainBridgeConfig, ReportAccountsPayable};
    use crate::sub_lib::configurator::NewPasswordMessage;
    use crate::sub_lib::cryptde::{PlainData, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
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
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use crate::sub_lib::ui_gateway::UiGatewayConfig;
    use crate::test_utils::main_cryptde;
    use crate::test_utils::make_wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::pure_test_utils::{CleanUpMessage, DummyActor};
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::{alias_cryptde, rate_pack};
    use crate::{hopper, proxy_client, proxy_server, stream_handler_pool, ui_gateway};
    use actix::System;
    use crossbeam_channel::bounded;
    use log::LevelFilter;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::crash_point::CrashPoint;
    use masq_lib::messages::{ToMessageBody, UiCrashRequest, UiDescriptorRequest};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use masq_lib::ui_gateway::NodeToUiMessage;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::net::{IpAddr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;
    use std::ptr::addr_of;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[derive(Default)]
    struct ActorSystemFactoryToolsMock {
        prepare_initial_messages_params: Arc<
            Mutex<
                Vec<(
                    Box<dyn CryptDE>,
                    Box<dyn CryptDE>,
                    BootstrapperConfig,
                    Box<dyn ActorFactory>,
                )>,
            >,
        >,
        prepare_initial_messages_results: RefCell<Vec<StreamHandlerPoolSubs>>,
        main_cryptde_ref_results: RefCell<Vec<&'static dyn CryptDE>>,
        alias_cryptde_ref_results: RefCell<Vec<&'static dyn CryptDE>>,
        database_chain_assertion_params: Arc<Mutex<Vec<Chain>>>,
        compare_persistent_config_to_pointer: RefCell<Vec<*const dyn PersistentConfiguration>>,
    }

    impl ActorSystemFactoryTools for ActorSystemFactoryToolsMock {
        fn prepare_initial_messages(
            &self,
            main_cryptde: &'static dyn CryptDE,
            alias_cryptde: &'static dyn CryptDE,
            config: BootstrapperConfig,
            actor_factory: Box<dyn ActorFactory>,
        ) -> StreamHandlerPoolSubs {
            self.prepare_initial_messages_params.lock().unwrap().push((
                Box::new(<&CryptDENull>::from(main_cryptde).clone()),
                Box::new(<&CryptDENull>::from(alias_cryptde).clone()),
                config,
                actor_factory,
            ));
            self.prepare_initial_messages_results.borrow_mut().remove(0)
        }

        fn main_cryptde_ref(&self) -> &'static dyn CryptDE {
            self.main_cryptde_ref_results.borrow_mut().remove(0)
        }

        fn alias_cryptde_ref(&self) -> &'static dyn CryptDE {
            self.alias_cryptde_ref_results.borrow_mut().remove(0)
        }

        fn database_chain_assertion(
            &self,
            chain: Chain,
            persistent_config: &dyn PersistentConfiguration,
        ) {
            self.database_chain_assertion_params
                .lock()
                .unwrap()
                .push(chain);
            assert_eq!(
                self.compare_persistent_config_to_pointer
                    .borrow_mut()
                    .remove(0),
                addr_of!(*persistent_config)
            )
        }
    }

    impl ActorSystemFactoryToolsMock {
        pub fn main_cryptde_ref_result(self, result: &'static dyn CryptDE) -> Self {
            self.main_cryptde_ref_results.borrow_mut().push(result);
            self
        }

        pub fn alias_cryptde_ref_result(self, result: &'static dyn CryptDE) -> Self {
            self.alias_cryptde_ref_results.borrow_mut().push(result);
            self
        }

        pub fn database_chain_assertion_params(
            mut self,
            real_param: &Arc<Mutex<Vec<Chain>>>,
            to_compare_for_in_place_param: *const dyn PersistentConfiguration,
        ) -> Self {
            self.database_chain_assertion_params = real_param.clone();
            self.compare_persistent_config_to_pointer
                .borrow_mut()
                .push(to_compare_for_in_place_param);
            self
        }

        pub fn prepare_initial_messages_params(
            mut self,
            params: &Arc<
                Mutex<
                    Vec<(
                        Box<dyn CryptDE>,
                        Box<dyn CryptDE>,
                        BootstrapperConfig,
                        Box<dyn ActorFactory>,
                    )>,
                >,
            >,
        ) -> Self {
            self.prepare_initial_messages_params = params.clone();
            self
        }

        pub fn prepare_initial_messages_result(self, result: StreamHandlerPoolSubs) -> Self {
            self.prepare_initial_messages_results
                .borrow_mut()
                .push(result);
            self
        }
    }

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
            config: &BootstrapperConfig,
        ) -> (DispatcherSubs, Recipient<PoolBindMessage>) {
            self.parameters
                .dispatcher_params
                .lock()
                .unwrap()
                .get_or_insert(config.clone());
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.dispatcher);
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
            config: &BootstrapperConfig,
        ) -> ProxyServerSubs {
            self.parameters
                .proxy_server_params
                .lock()
                .unwrap()
                .get_or_insert((main_cryptde, alias_cryptde, config.clone()));
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.proxy_server);
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
                node_from_ui: recipient!(addr, NodeFromUiMessage),
            }
        }

        fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs {
            self.parameters
                .hopper_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.hopper);
            HopperSubs {
                bind: recipient!(addr, BindMessage),
                from_hopper_client: recipient!(addr, IncipientCoresPackage),
                from_hopper_client_no_lookup: addr
                    .clone()
                    .recipient::<NoLookupIncipientCoresPackage>(),
                from_dispatcher: recipient!(addr, InboundClientData),
                node_from_ui: recipient!(addr, NodeFromUiMessage),
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
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.neighborhood);
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
            data_directory: &Path,
            _db_initializer: &dyn DbInitializer,
            _banned_cache_loader: &dyn BannedCacheLoader,
        ) -> AccountantSubs {
            self.parameters
                .accountant_params
                .lock()
                .unwrap()
                .get_or_insert((config.clone(), data_directory.to_path_buf()));
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.accountant);
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

        fn make_and_start_ui_gateway(&self, config: &BootstrapperConfig) -> UiGatewaySubs {
            self.parameters
                .ui_gateway_params
                .lock()
                .unwrap()
                .get_or_insert(config.ui_gateway_config.clone());
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.ui_gateway);
            UiGatewaySubs {
                bind: recipient!(addr, BindMessage),
                node_from_ui_message_sub: recipient!(addr, NodeFromUiMessage),
                node_to_ui_message_sub: recipient!(addr, NodeToUiMessage),
            }
        }

        fn make_and_start_stream_handler_pool(
            &self,
            _: &BootstrapperConfig,
        ) -> StreamHandlerPoolSubs {
            let addr = start_recorder_refcell_opt(&self.stream_handler_pool);
            make_stream_handler_pool_subs_from_an_addr(addr)
        }

        fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs {
            self.parameters
                .proxy_client_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.proxy_client);
            ProxyClientSubs {
                bind: recipient!(addr, BindMessage),
                from_hopper: addr
                    .clone()
                    .recipient::<ExpiredCoresPackage<ClientRequestPayload_0v1>>(),
                inbound_server_data: recipient!(addr, InboundServerData),
                dns_resolve_failed: recipient!(addr, DnsResolveFailure_0v1),
                node_from_ui: recipient!(addr, NodeFromUiMessage),
            }
        }

        fn make_and_start_blockchain_bridge(
            &self,
            config: &BootstrapperConfig,
        ) -> BlockchainBridgeSubs {
            self.parameters
                .blockchain_bridge_params
                .lock()
                .unwrap()
                .get_or_insert(config.clone());
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.blockchain_bridge);
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
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.configurator);
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
        dispatcher_params: Arc<Mutex<Option<BootstrapperConfig>>>,
        proxy_client_params: Arc<Mutex<Option<ProxyClientConfig>>>,
        proxy_server_params:
            Arc<Mutex<Option<(&'a dyn CryptDE, &'a dyn CryptDE, BootstrapperConfig)>>>,
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
                dispatcher_params: Arc::new(Mutex::new(None)),
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
            ui_gateway_config: UiGatewayConfig { ui_port: 5335 },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            node_descriptor_opt: Some("uninitialized".to_string()),
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
        let persistent_config =
            PersistentConfigurationMock::default().chain_name_result("eth-ropsten".to_string());
        Bootstrapper::pub_initialize_cryptdes_for_testing(
            &Some(main_cryptde()),
            &Some(alias_cryptde()),
        );
        let subject = ActorSystemFactoryReal {};

        let system = System::new("test");
        subject.make_and_start_actors(
            config,
            Box::new(actor_factory),
            &persistent_config,
            &ActorSystemFactoryToolsReal,
        );
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
            ui_gateway_config: UiGatewayConfig { ui_port: 5335 },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            node_descriptor_opt: Some("NODE-DESCRIPTOR".to_string()),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::ZeroHop,
            },
        };
        let system = System::new("MASQNode");

        let _ = ActorSystemFactoryToolsReal.prepare_initial_messages(
            main_cryptde(),
            alias_cryptde(),
            config.clone(),
            Box::new(actor_factory),
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
        let (actual_main_cryptde, actual_alias_cryptde, bootstrapper_config) =
            Parameters::get(parameters.proxy_server_params);
        check_cryptde(actual_main_cryptde);
        check_cryptde(actual_alias_cryptde);
        assert_ne!(
            actual_main_cryptde.public_key(),
            actual_alias_cryptde.public_key()
        );
        assert_eq!(
            bootstrapper_config
                .neighborhood_config
                .mode
                .is_decentralized(),
            false
        );
        assert_eq!(
            bootstrapper_config.consuming_wallet,
            Some(make_wallet("consuming"))
        );
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
        let dispatcher_param = Parameters::get(parameters.dispatcher_params);
        assert_eq!(
            dispatcher_param.node_descriptor_opt,
            Some("NODE-DESCRIPTOR".to_string())
        );
        let blockchain_bridge_param = Parameters::get(parameters.blockchain_bridge_params);
        assert_eq!(
            blockchain_bridge_param.blockchain_bridge_config,
            BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1,
            }
        );
        assert_eq!(
            blockchain_bridge_param.consuming_wallet,
            Some(make_wallet("consuming"))
        );
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
            ui_gateway_config: UiGatewayConfig { ui_port: 5335 },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            node_descriptor_opt: Some("NODE-DESCRIPTOR".to_string()),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::ConsumeOnly(vec![]),
            },
        };
        let system = System::new("MASQNode");

        let _ = ActorSystemFactoryToolsReal.prepare_initial_messages(
            main_cryptde(),
            alias_cryptde(),
            config.clone(),
            Box::new(actor_factory),
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
            ui_gateway_config: UiGatewayConfig { ui_port: 5335 },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1,
            },
            port_configurations: HashMap::new(),
            db_password_opt: None,
            clandestine_port_opt: None,
            earning_wallet: make_wallet("earning"),
            consuming_wallet: None,
            data_directory: PathBuf::new(),
            node_descriptor_opt: Some("NODE-DESCRIPTOR".to_string()),
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
        let system = System::new("MASQNode");

        let _ = ActorSystemFactoryToolsReal.prepare_initial_messages(
            main_cryptde(),
            alias_cryptde(),
            config.clone(),
            Box::new(actor_factory),
        );

        System::current().stop();
        system.run();
        let (_, _, bootstrapper_config) = Parameters::get(parameters.proxy_server_params);
        assert_eq!(bootstrapper_config.consuming_wallet, None);
    }

    #[test]
    fn proxy_server_drags_down_the_whole_system_due_to_local_panic() {
        let closure = || {
            let mut bootstrapper_config = BootstrapperConfig::default();
            bootstrapper_config.crash_point = CrashPoint::Message;
            let subscribers = ActorFactoryReal {}.make_and_start_proxy_server(
                main_cryptde(),
                alias_cryptde(),
                &bootstrapper_config,
            );
            subscribers.node_from_ui
        };

        panic_in_arbiter_thread_versus_system(Box::new(closure), proxy_server::CRASH_KEY)
    }

    #[test]
    fn proxy_client_drags_down_the_whole_system_due_to_local_panic() {
        let closure = || {
            let proxy_cl_config = ProxyClientConfig {
                cryptde: main_cryptde(),
                dns_servers: vec![SocketAddr::V4(
                    SocketAddrV4::from_str("1.1.1.1:45").unwrap(),
                )],
                exit_service_rate: 50,
                crashable: true,
                exit_byte_rate: 50,
            };
            let subscribers = ActorFactoryReal {}.make_and_start_proxy_client(proxy_cl_config);
            subscribers.node_from_ui
        };

        panic_in_arbiter_thread_versus_system(Box::new(closure), proxy_client::CRASH_KEY)
    }

    #[test]
    fn hopper_drags_down_the_whole_system_due_to_local_panic() {
        let closure = || {
            let hopper_config = HopperConfig {
                main_cryptde: main_cryptde(),
                alias_cryptde: alias_cryptde(),
                per_routing_service: 100,
                per_routing_byte: 50,
                is_decentralized: false,
                crashable: true,
            };
            let subscribers = ActorFactoryReal {}.make_and_start_hopper(hopper_config);
            subscribers.node_from_ui
        };

        panic_in_arbiter_thread_versus_system(Box::new(closure), hopper::CRASH_KEY)
    }

    #[test]
    fn ui_gateway_drags_down_the_whole_system_due_to_local_panic() {
        let closure = || {
            let mut bootstrapper_config = BootstrapperConfig::default();
            bootstrapper_config.crash_point = CrashPoint::Message;
            let subscribers = ActorFactoryReal {}.make_and_start_ui_gateway(&bootstrapper_config);
            subscribers.node_from_ui_message_sub
        };

        panic_in_arbiter_thread_versus_system(Box::new(closure), ui_gateway::CRASH_KEY)
    }

    #[test]
    fn stream_handler_pool_drags_down_the_whole_system_due_to_local_panic() {
        let closure = || {
            let mut bootstrapper_config = BootstrapperConfig::default();
            bootstrapper_config.crash_point = CrashPoint::Message;
            let subscribers =
                ActorFactoryReal {}.make_and_start_stream_handler_pool(&bootstrapper_config);
            subscribers.node_from_ui_sub
        };

        panic_in_arbiter_thread_versus_system(Box::new(closure), stream_handler_pool::CRASH_KEY)
    }

    fn panic_in_arbiter_thread_versus_system<F>(actor_initialization: Box<F>, actor_crash_key: &str)
    where
        F: FnOnce() -> Recipient<NodeFromUiMessage>,
    {
        let (mercy_signal_tx, mercy_signal_rx) = bounded(1);
        let system = System::new("test");
        let dummy_actor = DummyActor::new(Some(mercy_signal_tx));
        let dummy_addr = Arbiter::start(|_| dummy_actor);
        let ui_node_addr = actor_initialization();
        let crash_request = UiCrashRequest {
            actor: actor_crash_key.to_string(),
            panic_message: format!(
                "Testing a panic in the arbiter's thread for {}",
                actor_crash_key
            ),
        };
        let actor_message = NodeFromUiMessage {
            client_id: 1,
            body: crash_request.tmb(123),
        };
        dummy_addr
            .try_send(CleanUpMessage { sleep_ms: 1500 })
            .unwrap();
        ui_node_addr.try_send(actor_message).unwrap();
        system.run();
        assert!(
            mercy_signal_rx.try_recv().is_err(),
            "{} while panicking is unable to shut the system down",
            actor_crash_key
        )
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

    #[test]
    fn database_chain_validity_happy_path() {
        let chain = DEFAULT_CHAIN;
        let persistent_config =
            PersistentConfigurationMock::default().chain_name_result("eth-mainnet".to_string());

        let _ = ActorSystemFactoryToolsReal.database_chain_assertion(chain, &persistent_config);
    }

    #[test]
    #[should_panic(
        expected = "Database with the wrong chain name detected; expected: eth-ropsten, was: eth-mainnet"
    )]
    fn make_and_start_actors_will_not_tolerate_differences_in_setup_chain_and_database_chain() {
        let mut bootstrapper_config = BootstrapperConfig::new();
        bootstrapper_config.blockchain_bridge_config.chain = TEST_DEFAULT_CHAIN;
        let persistent_config =
            PersistentConfigurationMock::default().chain_name_result("eth-mainnet".to_string());
        Bootstrapper::pub_initialize_cryptdes_for_testing(
            &Some(main_cryptde().clone()),
            &Some(alias_cryptde().clone()),
        );

        let _ = ActorSystemFactoryReal {}.make_and_start_actors(
            bootstrapper_config,
            Box::new(ActorFactoryReal {}),
            &persistent_config,
            &ActorSystemFactoryToolsReal,
        );
    }

    #[test]
    fn make_and_start_actors_happy_path() {
        let database_chain_assertion_params_arc = Arc::new(Mutex::new(vec![]));
        let prepare_initial_messages_params_arc = Arc::new(Mutex::new(vec![]));
        let (recorder, _, recording_arc) = make_recorder();
        let stream_holder_pool_subs = make_stream_handler_pool_subs_from(Some(recorder));
        let mut bootstrapper_config = BootstrapperConfig::new();
        let irrelevant_data_dir = PathBuf::new().join("big_directory/small_directory");
        bootstrapper_config.blockchain_bridge_config.chain = Chain::PolyMainnet;
        bootstrapper_config.data_directory = irrelevant_data_dir.clone();
        bootstrapper_config.db_password_opt = Some("chameleon".to_string());
        let main_cryptde = main_cryptde();
        let main_cryptde_public_key_before = public_key_for_dyn_cryptde_being_null(main_cryptde);
        let alias_cryptde = alias_cryptde();
        let alias_cryptde_public_key_before = public_key_for_dyn_cryptde_being_null(alias_cryptde);
        let actor_factory = Box::new(ActorFactoryReal {}) as Box<dyn ActorFactory>;
        let actor_factory_raw_address = addr_of!(*actor_factory);
        let persistent_config = PersistentConfigurationMock::default();
        let persistent_config_raw_address = addr_of!(persistent_config);
        let tools = ActorSystemFactoryToolsMock::default()
            .main_cryptde_ref_result(main_cryptde)
            .alias_cryptde_ref_result(alias_cryptde)
            .database_chain_assertion_params(
                &database_chain_assertion_params_arc,
                persistent_config_raw_address,
            )
            .prepare_initial_messages_params(&prepare_initial_messages_params_arc)
            .prepare_initial_messages_result(stream_holder_pool_subs);

        let result = ActorSystemFactoryReal {}.make_and_start_actors(
            bootstrapper_config,
            Box::new(ActorFactoryReal {}),
            &persistent_config,
            &tools,
        );

        let database_chain_assertion_params = database_chain_assertion_params_arc.lock().unwrap();
        assert_eq!(*database_chain_assertion_params, vec![Chain::PolyMainnet]);
        let mut prepare_initial_messages_params =
            prepare_initial_messages_params_arc.lock().unwrap();
        let (
            main_cryptde_after,
            alias_cryptde_after,
            bootstrapper_config_after,
            actor_factory_after,
        ) = prepare_initial_messages_params.remove(0);
        assert!(prepare_initial_messages_params.is_empty());
        let main_cryptde_public_key_after =
            public_key_for_dyn_cryptde_being_null(main_cryptde_after.as_ref());
        assert_eq!(
            main_cryptde_public_key_after,
            main_cryptde_public_key_before
        );
        let alias_cryptde_public_key_after =
            public_key_for_dyn_cryptde_being_null(alias_cryptde_after.as_ref());
        assert_eq!(
            alias_cryptde_public_key_after,
            alias_cryptde_public_key_before
        );
        assert_eq!(
            bootstrapper_config_after.data_directory,
            irrelevant_data_dir
        );
        assert_eq!(
            bootstrapper_config_after.db_password_opt,
            Some("chameleon".to_string())
        );
        assert_eq!(addr_of!(*actor_factory_after), actor_factory_raw_address);
        let system = System::new("make_and_start_actors_happy_path");
        let msg_of_irrelevant_choice = NodeFromUiMessage {
            client_id: 5,
            body: UiDescriptorRequest {}.tmb(1),
        };
        result
            .node_from_ui_sub
            .try_send(msg_of_irrelevant_choice.clone())
            .unwrap();
        System::current().stop_with_code(0);
        system.run();
        let recording = recording_arc.lock().unwrap();
        let msg = recording.get_record::<NodeFromUiMessage>(0);
        assert_eq!(msg, &msg_of_irrelevant_choice)
    }

    fn public_key_for_dyn_cryptde_being_null(cryptde: &dyn CryptDE) -> &PublicKey {
        let null_cryptde = <&CryptDENull>::from(cryptde);
        null_cryptde.public_key()
    }
}
