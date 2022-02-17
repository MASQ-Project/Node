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
use crate::sub_lib::neighborhood::{NeighborhoodMode, NeighborhoodSubs};
use crate::sub_lib::peer_actors::{BindMessage, StartMessage};
use crate::sub_lib::peer_actors::{NewPublicIp, PeerActors};
use crate::sub_lib::proxy_client::ProxyClientConfig;
use crate::sub_lib::proxy_client::ProxyClientSubs;
use crate::sub_lib::proxy_server::ProxyServerSubs;
use crate::sub_lib::ui_gateway::UiGatewaySubs;
use actix::Recipient;
use actix::{Addr, Arbiter};
use automap_lib::comm_layer::AutomapError;
use automap_lib::control_layer::automap_control::{
    AutomapChange, AutomapControl, AutomapControlReal, ChangeHandler,
};
use masq_lib::blockchains::chains::Chain;
use masq_lib::crash_point::CrashPoint;
use masq_lib::ui_gateway::NodeFromUiMessage;
use masq_lib::utils::{exit_process, AutomapProtocol};
use std::net::{IpAddr, Ipv4Addr};
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

pub struct ActorSystemFactoryReal;

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

impl ActorSystemFactoryReal {
    pub fn new() -> Self {
        Self {}
    }
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

pub struct ActorSystemFactoryToolsReal {
    automap_control_factory: Box<dyn AutomapControlFactory>,
}

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
                    exit_service_rate: config
                        .neighborhood_config
                        .mode
                        .rate_pack()
                        .clone()
                        .exit_service_rate,
                    exit_byte_rate: config.neighborhood_config.mode.rate_pack().exit_byte_rate,
                    crashable: is_crashable(&config),
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
            crashable: is_crashable(&config),
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

        self.start_automap(
            &config,
            vec![
                peer_actors.neighborhood.new_public_ip.clone(),
                peer_actors.dispatcher.new_ip_sub.clone(),
            ],
        );

        //after we've bound all the actors, send start messages to any actors that need it
        send_start_message!(peer_actors.neighborhood);

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

impl ActorSystemFactoryToolsReal {
    pub fn new() -> Self {
        Self {
            automap_control_factory: Box::new(AutomapControlFactoryReal::new()),
        }
    }

    fn notify_of_public_ip_change(
        new_ip_recipients: &[Recipient<NewPublicIp>],
        new_public_ip: IpAddr,
    ) {
        new_ip_recipients.iter().for_each(|r| {
            r.try_send(NewPublicIp {
                new_ip: new_public_ip,
            })
            .expect("NewPublicIp recipient is dead")
        });
    }

    fn handle_housekeeping_thread_error(error: AutomapError) {
        Self::handle_automap_error("", error);
    }

    fn handle_automap_error(prefix: &str, error: AutomapError) {
        exit_process(1, &format!("Automap failure: {}{:?}", prefix, error));
    }

    fn start_automap(
        &self,
        config: &BootstrapperConfig,
        new_ip_recipients: Vec<Recipient<NewPublicIp>>,
    ) {
        if let NeighborhoodMode::Standard(node_addr, _, _) = &config.neighborhood_config.mode {
            // If we already know the IP address, no need for Automap
            if node_addr.ip_addr() != IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
                return;
            }
            let change_handler = move |change: AutomapChange| match change {
                AutomapChange::NewIp(new_public_ip) => {
                    exit_process(
                        1,
                        format! ("IP change to {} reported from ISP. We can't handle that until GH-499. Going down...", new_public_ip).as_str()
                    );
                }
                AutomapChange::Error(e) => Self::handle_housekeeping_thread_error(e),
            };
            let mut automap_control = self
                .automap_control_factory
                .make(config.mapping_protocol_opt, Box::new(change_handler));
            let public_ip = match automap_control.get_public_ip() {
                Ok(ip) => ip,
                Err(e) => {
                    Self::handle_automap_error("Can't get public IP - ", e);
                    return; // never happens; handle_automap_error doesn't return.
                }
            };
            Self::notify_of_public_ip_change(new_ip_recipients.as_slice(), public_ip);
            node_addr.ports().iter().for_each(|port| {
                if let Err(e) = automap_control.add_mapping(*port) {
                    Self::handle_automap_error(
                        &format!("Can't map port {} through the router - ", port),
                        e,
                    );
                }
            });
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
        let node_descriptor = config.node_descriptor.clone();
        let crashable = is_crashable(config);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Dispatcher> =
            arbiter.start(move |_| Dispatcher::new(node_descriptor, crashable));
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
        let consuming_wallet_balance = if config.consuming_wallet_opt.is_some() {
            Some(0)
        } else {
            None
        };
        let crashable = is_crashable(config);
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
        let pending_payable_dao_factory = Accountant::dao_factory(data_directory);
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
                Box::new(pending_payable_dao_factory),
                Box::new(banned_dao_factory),
                Box::new(config_dao_factory),
            )
        });
        Accountant::make_subs_from(&addr)
    }

    fn make_and_start_ui_gateway(&self, config: &BootstrapperConfig) -> UiGatewaySubs {
        let crashable = is_crashable(config);
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
        let crashable = is_crashable(config);
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
        let crashable = is_crashable(config);
        let wallet_opt = config.consuming_wallet_opt.clone();
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
        let crashable = is_crashable(config);
        let arbiter = Arbiter::builder().stop_system_on_panic(true);
        let addr: Addr<Configurator> =
            arbiter.start(move |_| Configurator::new(data_directory, crashable));
        ConfiguratorSubs {
            bind: recipient!(addr, BindMessage),
            node_from_ui_sub: recipient!(addr, NodeFromUiMessage),
        }
    }
}

fn is_crashable(config: &BootstrapperConfig) -> bool {
    config.crash_point == CrashPoint::Message
}

pub trait AutomapControlFactory: Send {
    fn make(
        &self,
        usual_protocol_opt: Option<AutomapProtocol>,
        change_handler: ChangeHandler,
    ) -> Box<dyn AutomapControl>;
}

pub struct AutomapControlFactoryReal {}

impl AutomapControlFactory for AutomapControlFactoryReal {
    fn make(
        &self,
        usual_protocol_opt: Option<AutomapProtocol>,
        change_handler: ChangeHandler,
    ) -> Box<dyn AutomapControl> {
        Box::new(AutomapControlReal::new(usual_protocol_opt, change_handler))
    }
}

impl AutomapControlFactoryReal {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct AutomapControlFactoryNull {}

impl AutomapControlFactory for AutomapControlFactoryNull {
    fn make(
        &self,
        _usual_protocol_opt: Option<AutomapProtocol>,
        _change_handler: ChangeHandler,
    ) -> Box<dyn AutomapControl> {
        panic!("Should never call make() on an AutomapControlFactoryNull.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::DEFAULT_PENDING_TOO_LONG_SEC;
    use crate::bootstrapper::{Bootstrapper, RealUser};
    use crate::database::connection_wrapper::ConnectionWrapper;
    use crate::node_test_utils::{
        make_stream_handler_pool_subs_from, make_stream_handler_pool_subs_from_recorder,
        start_recorder_refcell_opt,
    };
    use crate::sub_lib::accountant::AccountantConfig;
    use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
    use crate::sub_lib::cryptde::{PlainData, PublicKey};
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::sub_lib::dispatcher::{InboundClientData, StreamShutdownMsg};
    use crate::sub_lib::neighborhood::NeighborhoodConfig;
    use crate::sub_lib::neighborhood::NeighborhoodMode;
    use crate::sub_lib::neighborhood::NodeDescriptor;
    use crate::sub_lib::neighborhood::DEFAULT_RATE_PACK;
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::peer_actors::StartMessage;
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use crate::sub_lib::ui_gateway::UiGatewayConfig;
    use crate::test_utils::automap_mocks::{AutomapControlFactoryMock, AutomapControlMock};
    use crate::test_utils::main_cryptde;
    use crate::test_utils::make_wallet;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::pure_test_utils::{CleanUpMessage, DummyActor};
    use crate::test_utils::recorder::{
        make_accountant_subs_from_recorder, make_blockchain_bridge_subs_from,
        make_configurator_subs_from, make_hopper_subs_from, make_neighborhood_subs_from,
        make_proxy_client_subs_from, make_proxy_server_subs_from,
        make_ui_gateway_subs_from_recorder, Recording,
    };
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::{alias_cryptde, rate_pack};
    use crate::{hopper, proxy_client, proxy_server, stream_handler_pool, ui_gateway};
    use actix::{Actor, Arbiter, System};
    use automap_lib::control_layer::automap_control::AutomapChange;
    use crossbeam_channel::bounded;
    use log::LevelFilter;
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::crash_point::CrashPoint;
    use masq_lib::messages::{ToMessageBody, UiCrashRequest, UiDescriptorRequest};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use masq_lib::utils::running_test;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::convert::TryFrom;
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
                new_ip_sub: recipient!(addr, NewPublicIp),
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
            let addr: Addr<Recorder> = ActorFactoryMock::start_recorder(&self.proxy_server);
            make_proxy_server_subs_from(&addr)
        }

        fn make_and_start_hopper(&self, config: HopperConfig) -> HopperSubs {
            self.parameters
                .hopper_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.hopper);
            make_hopper_subs_from(&addr)
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
            make_neighborhood_subs_from(&addr)
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
            make_accountant_subs_from_recorder(&addr)
        }

        fn make_and_start_ui_gateway(&self, config: &BootstrapperConfig) -> UiGatewaySubs {
            self.parameters
                .ui_gateway_params
                .lock()
                .unwrap()
                .get_or_insert(config.ui_gateway_config.clone());
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.ui_gateway);
            make_ui_gateway_subs_from_recorder(&addr)
        }

        fn make_and_start_stream_handler_pool(
            &self,
            _: &BootstrapperConfig,
        ) -> StreamHandlerPoolSubs {
            let addr = start_recorder_refcell_opt(&self.stream_handler_pool);
            make_stream_handler_pool_subs_from_recorder(&addr)
        }

        fn make_and_start_proxy_client(&self, config: ProxyClientConfig) -> ProxyClientSubs {
            self.parameters
                .proxy_client_params
                .lock()
                .unwrap()
                .get_or_insert(config);
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.proxy_client);
            make_proxy_client_subs_from(&addr)
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
            make_blockchain_bridge_subs_from(&addr)
        }

        fn make_and_start_configurator(&self, config: &BootstrapperConfig) -> ConfiguratorSubs {
            self.parameters
                .configurator_params
                .lock()
                .unwrap()
                .get_or_insert(config.clone());
            let addr: Addr<Recorder> = start_recorder_refcell_opt(&self.configurator);
            make_configurator_subs_from(&addr)
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

        fn start_recorder(recorder: &RefCell<Option<Recorder>>) -> Addr<Recorder> {
            recorder.borrow_mut().take().unwrap().start()
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
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
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
            consuming_wallet_opt: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            node_descriptor: NodeDescriptor::default(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            mapping_protocol_opt: None,
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
        let subject = ActorSystemFactoryReal::new();
        let mut tools = ActorSystemFactoryToolsReal::new();
        tools.automap_control_factory = Box::new(
            AutomapControlFactoryMock::new().make_result(
                AutomapControlMock::new()
                    .get_public_ip_result(Ok(IpAddr::from_str("1.2.3.4").unwrap()))
                    .add_mapping_result(Ok(())),
            ),
        );

        let system = System::new("test");
        subject.make_and_start_actors(config, Box::new(actor_factory), &persistent_config, &tools);
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
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
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
            consuming_wallet_opt: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            node_descriptor: NodeDescriptor::try_from ((main_cryptde(), "masq://polygon-mainnet:OHsC2CAm4rmfCkaFfiynwxflUgVTJRb2oY5mWxNCQkY@172.50.48.6:9342")).unwrap(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            mapping_protocol_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), &[1234, 2345]),
                    vec![],
                    rate_pack(100),
                ),
            },
        };
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = ActorSystemFactoryToolsReal::new();
        subject.automap_control_factory = Box::new(
            AutomapControlFactoryMock::new().make_result(
                AutomapControlMock::new()
                    .get_public_ip_result(Ok(IpAddr::from_str("1.2.3.4").unwrap()))
                    .add_mapping_params(&add_mapping_params_arc)
                    .add_mapping_result(Ok(()))
                    .add_mapping_result(Ok(())),
            ),
        );

        let _ = subject.prepare_initial_messages(
            main_cryptde(),
            alias_cryptde(),
            config.clone(),
            Box::new(actor_factory),
        );

        let system = System::new("MASQNode");
        System::current().stop();
        system.run();
        check_bind_message(&recordings.dispatcher, false);
        check_bind_message(&recordings.hopper, false);
        check_bind_message(&recordings.proxy_client, false);
        check_bind_message(&recordings.proxy_server, false);
        check_bind_message(&recordings.neighborhood, false);
        check_bind_message(&recordings.ui_gateway, false);
        check_bind_message(&recordings.accountant, false);
        check_new_ip_message(
            &recordings.dispatcher,
            IpAddr::from_str("1.2.3.4").unwrap(),
            2,
        );
        check_new_ip_message(
            &recordings.neighborhood,
            IpAddr::from_str("1.2.3.4").unwrap(),
            1,
        );
        check_start_message(&recordings.neighborhood, 2);
        let hopper_config = Parameters::get(parameters.hopper_params);
        check_cryptde(hopper_config.main_cryptde);
        assert_eq!(hopper_config.per_routing_service, 102);
        assert_eq!(hopper_config.per_routing_byte, 101);
        let proxy_client_config = Parameters::get(parameters.proxy_client_params);
        check_cryptde(proxy_client_config.cryptde);
        assert_eq!(proxy_client_config.exit_service_rate, 104);
        assert_eq!(proxy_client_config.exit_byte_rate, 103);
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
            true
        );
        assert_eq!(
            bootstrapper_config.consuming_wallet_opt,
            Some(make_wallet("consuming"))
        );
        let (cryptde, neighborhood_config) = Parameters::get(parameters.neighborhood_params);
        check_cryptde(cryptde);
        assert_eq!(
            neighborhood_config.neighborhood_config,
            config.neighborhood_config
        );
        assert_eq!(
            neighborhood_config.consuming_wallet_opt,
            config.consuming_wallet_opt
        );
        let ui_gateway_config = Parameters::get(parameters.ui_gateway_params);
        assert_eq!(ui_gateway_config.ui_port, 5335);
        let dispatcher_param = Parameters::get(parameters.dispatcher_params);
        assert_eq!(
            dispatcher_param.node_descriptor,
            NodeDescriptor::try_from ((main_cryptde(), "masq://polygon-mainnet:OHsC2CAm4rmfCkaFfiynwxflUgVTJRb2oY5mWxNCQkY@172.50.48.6:9342")).unwrap()
        );
        let blockchain_bridge_param = Parameters::get(parameters.blockchain_bridge_params);
        assert_eq!(
            blockchain_bridge_param.blockchain_bridge_config,
            BlockchainBridgeConfig {
                blockchain_service_url_opt: None,
                chain: TEST_DEFAULT_CHAIN,
                gas_price: 1
            }
        );
        assert_eq!(
            blockchain_bridge_param.consuming_wallet_opt,
            Some(make_wallet("consuming"))
        );
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(*add_mapping_params, vec![1234, 2345]);
    }

    #[test]
    #[should_panic(
        expected = "1: IP change to 1.2.3.5 reported from ISP. We can't handle that until GH-499. Going down..."
    )]
    fn change_handler_panics_when_receiving_ip_change_from_isp() {
        running_test();
        let actor_factory = ActorFactoryMock::new();
        let mut config = BootstrapperConfig::default();
        config.neighborhood_config = NeighborhoodConfig {
            mode: NeighborhoodMode::Standard(
                NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), &[1234]),
                vec![],
                rate_pack(100),
            ),
        };
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = ActorSystemFactoryToolsReal::new();
        subject.automap_control_factory = Box::new(
            AutomapControlFactoryMock::new()
                .make_params(&make_params_arc)
                .make_result(
                    AutomapControlMock::new()
                        .get_public_ip_result(Ok(IpAddr::from_str("1.2.3.4").unwrap()))
                        .add_mapping_result(Ok(())),
                ),
        );

        let _ = subject.prepare_initial_messages(
            main_cryptde(),
            alias_cryptde(),
            config.clone(),
            Box::new(actor_factory),
        );

        let mut make_params = make_params_arc.lock().unwrap();
        let change_handler: ChangeHandler = make_params.remove(0).1;
        change_handler(AutomapChange::NewIp(IpAddr::from_str("1.2.3.5").unwrap()));

        let system = System::new("MASQNode");
        System::current().stop();
        system.run();
    }

    #[test]
    fn prepare_initial_messages_doesnt_start_up_proxy_client_or_automap_if_consume_only_mode() {
        let actor_factory = ActorFactoryMock::new();
        let recordings = actor_factory.get_recordings();
        let config = BootstrapperConfig {
            log_level: LevelFilter::Off,
            crash_point: CrashPoint::None,
            dns_servers: vec![],
            accountant_config: AccountantConfig {
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
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
            consuming_wallet_opt: Some(make_wallet("consuming")),
            data_directory: PathBuf::new(),
            node_descriptor: NodeDescriptor::try_from((main_cryptde(), "masq://polygon-mainnet:OHsC2CAm4rmfCkaFfiynwxflUgVTJRb2oY5mWxNCQkY@172.50.48.6:9342")).unwrap(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            mapping_protocol_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::ConsumeOnly(vec![]),
            },
        };
        let system = System::new("MASQNode");
        let mut subject = ActorSystemFactoryToolsReal::new();
        subject.automap_control_factory = Box::new(AutomapControlFactoryMock::new());

        let _ = subject.prepare_initial_messages(
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
        check_start_message(&recordings.neighborhood, 1);
    }

    #[test]
    fn start_automap_aborts_if_neighborhood_mode_is_standard_and_public_ip_is_supplied() {
        let mut subject = ActorSystemFactoryToolsReal::new();
        let automap_control = AutomapControlMock::new();
        subject.automap_control_factory =
            Box::new(AutomapControlFactoryMock::new().make_result(automap_control));
        let mut config = BootstrapperConfig::default();
        config.neighborhood_config.mode = NeighborhoodMode::Standard(
            NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &[1234]),
            vec![],
            DEFAULT_RATE_PACK,
        );
        let (recorder, _, _) = make_recorder();
        let new_ip_recipient = recorder.start().recipient();

        subject.start_automap(&config, vec![new_ip_recipient]);

        // no not-enough-results-provided error: test passes
    }

    #[test]
    #[should_panic(expected = "1: Automap failure: AllProtocolsFailed")]
    fn start_automap_change_handler_handles_remapping_errors_properly() {
        running_test();
        let mut subject = ActorSystemFactoryToolsReal::new();
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let automap_control = AutomapControlMock::new()
            .get_public_ip_result(Ok(IpAddr::from_str("1.2.3.4").unwrap()))
            .add_mapping_result(Ok(()));
        subject.automap_control_factory = Box::new(
            AutomapControlFactoryMock::new()
                .make_params(&make_params_arc)
                .make_result(automap_control),
        );
        let mut config = BootstrapperConfig::default();
        config.mapping_protocol_opt = None;
        config.neighborhood_config.mode = NeighborhoodMode::Standard(
            NodeAddr::new(&IpAddr::from_str("0.0.0.0").unwrap(), &[1234]),
            vec![],
            DEFAULT_RATE_PACK,
        );

        subject.start_automap(&config, vec![]);

        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(make_params[0].0, None);
        let system = System::new("test");
        let change_handler = &make_params[0].1;
        change_handler(AutomapChange::Error(AutomapError::AllProtocolsFailed(
            vec![],
        )));
        System::current().stop();
        system.run();
    }

    #[test]
    #[should_panic(expected = "1: Automap failure: Can't get public IP - AllProtocolsFailed")]
    fn start_automap_change_handler_handles_get_public_ip_errors_properly() {
        running_test();
        let mut subject = ActorSystemFactoryToolsReal::new();
        let automap_control = AutomapControlMock::new()
            .get_public_ip_result(Err(AutomapError::AllProtocolsFailed(vec![])));
        subject.automap_control_factory =
            Box::new(AutomapControlFactoryMock::new().make_result(automap_control));
        let mut config = BootstrapperConfig::default();
        config.mapping_protocol_opt = None;
        config.neighborhood_config.mode = NeighborhoodMode::Standard(
            NodeAddr::new(&IpAddr::from_str("0.0.0.0").unwrap(), &[1234]),
            vec![],
            DEFAULT_RATE_PACK,
        );

        subject.start_automap(&config, vec![]);

        let system = System::new("test");
        System::current().stop();
        system.run();
    }

    #[test]
    #[should_panic(
        expected = "1: Automap failure: Can't map port 1234 through the router - AllProtocolsFailed"
    )]
    fn start_automap_change_handler_handles_initial_mapping_error_properly() {
        running_test();
        let mut subject = ActorSystemFactoryToolsReal::new();
        let automap_control = AutomapControlMock::new()
            .get_public_ip_result(Ok(IpAddr::from_str("1.2.3.4").unwrap()))
            .add_mapping_result(Err(AutomapError::AllProtocolsFailed(vec![])));
        subject.automap_control_factory =
            Box::new(AutomapControlFactoryMock::new().make_result(automap_control));
        let mut config = BootstrapperConfig::default();
        config.mapping_protocol_opt = None;
        config.neighborhood_config.mode = NeighborhoodMode::Standard(
            NodeAddr::new(&IpAddr::from_str("0.0.0.0").unwrap(), &[1234]),
            vec![],
            DEFAULT_RATE_PACK,
        );

        subject.start_automap(&config, vec![]);

        let system = System::new("test");
        System::current().stop();
        system.run();
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
                payables_scan_interval: Duration::from_secs(100),
                receivables_scan_interval: Duration::from_secs(100),
                pending_payable_scan_interval: Duration::from_secs(100),
                when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
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
            consuming_wallet_opt: None,
            earning_wallet: make_wallet("earning"),
            data_directory: PathBuf::new(),
            main_cryptde_null_opt: None,
            alias_cryptde_null_opt: None,
            mapping_protocol_opt: None,
            real_user: RealUser::null(),
            neighborhood_config: NeighborhoodConfig {
                mode: NeighborhoodMode::Standard(
                    NodeAddr::new(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), &[]),
                    vec![],
                    rate_pack(100),
                ),
            },
            node_descriptor: Default::default(),
        };
        let subject = ActorSystemFactoryToolsReal::new();
        let system = System::new("MASQNode");

        let _ = subject.prepare_initial_messages(
            main_cryptde(),
            alias_cryptde(),
            config.clone(),
            Box::new(actor_factory),
        );

        System::current().stop();
        system.run();
        let (_, _, bootstrapper_config) = Parameters::get(parameters.proxy_server_params);
        assert_eq!(bootstrapper_config.consuming_wallet_opt, None);
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

    fn check_start_message(recording: &Arc<Mutex<Recording>>, idx: usize) {
        let _start_message = Recording::get::<StartMessage>(recording, idx);
    }

    fn check_new_ip_message(recording: &Arc<Mutex<Recording>>, new_ip: IpAddr, idx: usize) {
        let new_ip_message = Recording::get::<NewPublicIp>(recording, idx);
        assert_eq!(new_ip_message.new_ip, new_ip);
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

        let _ =
            ActorSystemFactoryToolsReal::new().database_chain_assertion(chain, &persistent_config);
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
        let subject = ActorSystemFactoryReal::new();

        let _ = subject.make_and_start_actors(
            bootstrapper_config,
            Box::new(ActorFactoryReal {}),
            &persistent_config,
            &ActorSystemFactoryToolsReal::new(),
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
        let subject = ActorSystemFactoryReal::new();

        let result = subject.make_and_start_actors(
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
