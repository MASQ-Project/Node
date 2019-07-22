// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::{DEFAULT_PAYABLE_SCAN_INTERVAL, DEFAULT_PAYMENT_RECEIVED_SCAN_INTERVAL};
use crate::actor_system_factory::ActorFactoryReal;
use crate::actor_system_factory::ActorSystemFactory;
use crate::actor_system_factory::ActorSystemFactoryReal;
use crate::blockchain::blockchain_interface::DEFAULT_CHAIN_ID;
use crate::config_dao::ConfigDaoReal;
use crate::crash_test_dummy::CrashTestDummy;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
use crate::discriminator::DiscriminatorFactory;
use crate::json_discriminator_factory::JsonDiscriminatorFactory;
use crate::listener_handler::ListenerHandler;
use crate::listener_handler::ListenerHandlerFactory;
use crate::listener_handler::ListenerHandlerFactoryReal;
use crate::node_configurator::node_configurator_standard::{
    NodeConfiguratorStandardPrivileged, NodeConfiguratorStandardUnprivileged,
};
use crate::node_configurator::NodeConfigurator;
use crate::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};
use crate::server_initializer::LoggerInitializerWrapper;
use crate::sub_lib::accountant;
use crate::sub_lib::accountant::AccountantConfig;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
use crate::sub_lib::crash_point::CrashPoint;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::cryptde_real::CryptDEReal;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::neighborhood::sentinel_ip_addr;
use crate::sub_lib::neighborhood::NeighborhoodConfig;
use crate::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use crate::sub_lib::socket_server::SocketServer;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
use crate::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use crate::sub_lib::wallet::Wallet;
use futures::try_ready;
use log::LevelFilter;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use std::vec::Vec;
use tokio::prelude::stream::futures_unordered::FuturesUnordered;
use tokio::prelude::Async;
use tokio::prelude::Future;
use tokio::prelude::Stream;

static mut CRYPTDE_BOX_OPT: Option<Box<CryptDE>> = None;

pub fn cryptde_ref() -> &'static dyn CryptDE {
    unsafe {
        CRYPTDE_BOX_OPT
            .as_ref()
            .expect("Internal error: CryptDE uninitialized")
            .as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct PortConfiguration {
    pub discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    pub is_clandestine: bool,
}

impl PortConfiguration {
    pub fn new(
        discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
        is_clandestine: bool,
    ) -> PortConfiguration {
        PortConfiguration {
            discriminator_factories,
            is_clandestine,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BootstrapperConfig {
    // These fields can be set while privileged without penalty
    pub log_level: LevelFilter,
    pub dns_servers: Vec<SocketAddr>,
    pub neighborhood_config: NeighborhoodConfig,
    pub accountant_config: AccountantConfig,
    pub crash_point: CrashPoint,
    pub clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    pub ui_gateway_config: UiGatewayConfig,
    pub blockchain_bridge_config: BlockchainBridgeConfig,
    pub port_configurations: HashMap<u16, PortConfiguration>,
    pub data_directory: PathBuf,
    pub cryptde_null_opt: Option<CryptDENull>,

    // These fields must be set without privilege: otherwise the database will be created as root
    pub clandestine_port_opt: Option<u16>,
    pub consuming_wallet: Option<Wallet>,
    pub earning_wallet: Wallet,
}

impl Default for BootstrapperConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl BootstrapperConfig {
    pub fn new() -> BootstrapperConfig {
        let chain_id = DEFAULT_CHAIN_ID;
        BootstrapperConfig {
            // These fields can be set while privileged without penalty
            log_level: LevelFilter::Off,
            dns_servers: vec![],
            neighborhood_config: NeighborhoodConfig {
                neighbor_configs: vec![],
                local_ip_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                clandestine_port_list: vec![],
                rate_pack: DEFAULT_RATE_PACK.clone(),
            },
            accountant_config: AccountantConfig {
                payable_scan_interval: Duration::from_secs(DEFAULT_PAYABLE_SCAN_INTERVAL),
                payment_received_scan_interval: Duration::from_secs(
                    DEFAULT_PAYMENT_RECEIVED_SCAN_INTERVAL,
                ),
            },
            crash_point: CrashPoint::None,
            clandestine_discriminator_factories: vec![],
            ui_gateway_config: UiGatewayConfig {
                ui_port: DEFAULT_UI_PORT,
                node_descriptor: String::from(""),
            },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url: None,
                chain_id,
            },
            port_configurations: HashMap::new(),
            data_directory: PathBuf::new(),
            cryptde_null_opt: None,

            // These fields must be set without privilege: otherwise the database will be created as root
            clandestine_port_opt: None,
            earning_wallet: accountant::DEFAULT_EARNING_WALLET.clone(),
            consuming_wallet: None,
        }
    }

    pub fn merge_unprivileged(&mut self, unprivileged: BootstrapperConfig) {
        self.clandestine_port_opt = unprivileged.clandestine_port_opt;
        self.earning_wallet = unprivileged.earning_wallet;
        self.consuming_wallet = unprivileged.consuming_wallet;
    }
}

// TODO: Consider splitting this into a piece that's meant for being root and a piece that's not.
pub struct Bootstrapper {
    listener_handler_factory: Box<dyn ListenerHandlerFactory>,
    listener_handlers: FuturesUnordered<Box<dyn ListenerHandler<Item = (), Error = ()>>>,
    actor_system_factory: Box<dyn ActorSystemFactory>,
    logger_initializer: Box<dyn LoggerInitializerWrapper>,
    config: BootstrapperConfig,
}

impl Future for Bootstrapper {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        try_ready!(CrashTestDummy::new(self.config.crash_point.clone()).poll());

        try_ready!(self.listener_handlers.poll());
        Ok(Async::Ready(()))
    }
}

impl SocketServer for Bootstrapper {
    fn name(&self) -> String {
        String::from("Dispatcher")
    }

    fn initialize_as_privileged(&mut self, args: &Vec<String>, streams: &mut StdStreams) {
        self.config = NodeConfiguratorStandardPrivileged {}.configure(args, streams);

        self.logger_initializer.init(self.config.log_level);
        self.listener_handlers =
            FuturesUnordered::<Box<dyn ListenerHandler<Item = (), Error = ()>>>::new();

        let port_configurations = self.config.port_configurations.clone();
        port_configurations
            .iter()
            .for_each(|(port, port_configuration)| {
                let mut listener_handler = self.listener_handler_factory.make();
                match listener_handler
                    .bind_port_and_configuration(*port, port_configuration.clone())
                {
                    Ok(()) => (),
                    Err(e) => panic!("Could not listen on port {}: {}", port, e.to_string()),
                }
                self.listener_handlers.push(listener_handler);
            });
    }

    fn initialize_as_unprivileged(&mut self, args: &Vec<String>, streams: &mut StdStreams) {
        // NOTE: The following line of code is not covered by unit tests
        fdlimit::raise_fd_limit();
        self.config
            .merge_unprivileged(NodeConfiguratorStandardUnprivileged {}.configure(args, streams));
        self.establish_clandestine_port();
        let cryptde_ref = Bootstrapper::initialize_cryptde(
            &self.config.cryptde_null_opt,
            self.config.blockchain_bridge_config.chain_id,
        );
        self.config.ui_gateway_config.node_descriptor = Bootstrapper::report_local_descriptor(
            cryptde_ref,
            self.config.neighborhood_config.local_ip_addr,
            self.config
                .neighborhood_config
                .clandestine_port_list
                .clone(),
            streams,
        );
        let stream_handler_pool_subs = self
            .actor_system_factory
            .make_and_start_actors(self.config.clone(), Box::new(ActorFactoryReal {}));

        for f in self.listener_handlers.iter_mut() {
            f.bind_subs(stream_handler_pool_subs.add_sub.clone());
        }
    }
}

impl Bootstrapper {
    pub fn new(logger_initializer: Box<LoggerInitializerWrapper>) -> Bootstrapper {
        Bootstrapper {
            listener_handler_factory: Box::new(ListenerHandlerFactoryReal::new()),
            listener_handlers:
                FuturesUnordered::<Box<dyn ListenerHandler<Item = (), Error = ()>>>::new(),
            actor_system_factory: Box::new(ActorSystemFactoryReal {}),
            logger_initializer,
            config: BootstrapperConfig::new(),
        }
    }

    #[cfg(test)] // The real one is private, but ActorSystemFactory needs to use it for testing
    pub fn pub_initialize_cryptde_for_testing(
        cryptde_null_opt: &Option<CryptDENull>,
    ) -> &'static dyn CryptDE {
        Self::initialize_cryptde(cryptde_null_opt, DEFAULT_CHAIN_ID)
    }

    fn initialize_cryptde(
        cryptde_null_opt: &Option<CryptDENull>,
        chain_id: u8,
    ) -> &'static dyn CryptDE {
        match cryptde_null_opt {
            Some(cryptde_null) => unsafe { CRYPTDE_BOX_OPT = Some(Box::new(cryptde_null.clone())) },
            None => unsafe { CRYPTDE_BOX_OPT = Some(Box::new(CryptDEReal::new(chain_id))) },
        }
        cryptde_ref()
    }

    fn report_local_descriptor(
        cryptde: &dyn CryptDE,
        ip_addr: IpAddr,
        ports: Vec<u16>,
        streams: &mut StdStreams<'_>,
    ) -> String {
        let port_strings: Vec<String> = ports.iter().map(|n| format!("{}", n)).collect();
        let port_list = port_strings.join(",");
        let encoded_public_key = cryptde.public_key_to_descriptor_fragment(cryptde.public_key());
        let descriptor = format!("{}:{}:{}", &encoded_public_key, ip_addr, port_list);
        let descriptor_msg = format!("SubstratumNode local descriptor: {}", descriptor);
        writeln!(streams.stdout, "{}", descriptor_msg).expect("Internal error");
        info!(Logger::new("Bootstrapper"), descriptor_msg);
        descriptor
    }

    fn establish_clandestine_port(&mut self) {
        if Self::is_zero_hop(&self.config) {
            return;
        }
        let conn = DbInitializerReal::new()
            .initialize(&self.config.data_directory)
            .expect("Cannot initialize database");
        let config_dao = ConfigDaoReal::new(conn);
        let persistent_config = PersistentConfigurationReal::new(Box::new(config_dao));
        if let Some(clandestine_port) = self.config.clandestine_port_opt {
            persistent_config.set_clandestine_port(clandestine_port)
        }
        let clandestine_port = persistent_config.clandestine_port();
        let mut listener_handler = self.listener_handler_factory.make();
        listener_handler
            .bind_port_and_configuration(
                clandestine_port,
                PortConfiguration {
                    discriminator_factories: vec![Box::new(JsonDiscriminatorFactory::new())],
                    is_clandestine: true,
                },
            )
            .expect("Failed to bind ListenerHandler to clandestine port");
        self.listener_handlers.push(listener_handler);
        self.config.neighborhood_config.clandestine_port_list = vec![clandestine_port];
        self.config
            .clandestine_discriminator_factories
            .push(Box::new(JsonDiscriminatorFactory::new()));
    }

    // TODO Examine this and make sure it won't ever cause problems with decentralized Nodes that don't specify --neighbors
    fn is_zero_hop(config: &BootstrapperConfig) -> bool {
        config.neighborhood_config.neighbor_configs.is_empty()
            && config.neighborhood_config.local_ip_addr == sentinel_ip_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor_system_factory::ActorFactory;
    use crate::config_dao::ConfigDaoReal;
    use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
    use crate::discriminator::Discriminator;
    use crate::discriminator::UnmaskedChunk;
    use crate::node_test_utils::extract_log;
    use crate::node_test_utils::make_stream_handler_pool_subs_from;
    use crate::node_test_utils::TestLogOwner;
    use crate::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};
    use crate::server_initializer::test_utils::LoggerInitializerWrapperMock;
    use crate::stream_handler_pool::StreamHandlerPoolSubs;
    use crate::stream_messages::AddStreamMsg;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::neighborhood::NodeDescriptor;
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::stream_connector::ConnectionInfo;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLog;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::RecordAwaiter;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use crate::test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use crate::test_utils::{assert_contains, ensure_node_home_directory_exists};
    use crate::test_utils::{cryptde, FakeStreamHolder};
    use actix::Recipient;
    use actix::System;
    use lazy_static::lazy_static;
    use regex::Regex;
    use std::cell::RefCell;
    use std::io;
    use std::io::ErrorKind;
    use std::marker::Sync;
    use std::net::SocketAddr;
    use std::ops::DerefMut;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use tokio;
    use tokio::prelude::Async;

    lazy_static! {
        static ref INITIALIZATION: Mutex<bool> = Mutex::new(false);
    }

    struct ListenerHandlerFactoryMock {
        log: TestLog,
        mocks: RefCell<Vec<Box<dyn ListenerHandler<Item = (), Error = ()>>>>,
    }

    unsafe impl Sync for ListenerHandlerFactoryMock {}

    impl ListenerHandlerFactory for ListenerHandlerFactoryMock {
        fn make(&self) -> Box<dyn ListenerHandler<Item = (), Error = ()>> {
            self.log.log(String::from("make ()"));
            self.mocks.borrow_mut().remove(0)
        }
    }

    impl ListenerHandlerFactoryMock {
        fn new() -> ListenerHandlerFactoryMock {
            ListenerHandlerFactoryMock {
                log: TestLog::new(),
                mocks: RefCell::new(vec![]),
            }
        }

        fn add(&mut self, mock: Box<dyn ListenerHandler<Item = (), Error = ()>>) {
            self.mocks.borrow_mut().push(mock)
        }
    }

    struct ListenerHandlerNull {
        log: Arc<Mutex<TestLog>>,
        bind_port_and_discriminator_factories_result: Option<io::Result<()>>,
        port_configuration_parameter: Option<PortConfiguration>,
        add_stream_sub: Option<Recipient<AddStreamMsg>>,
        add_stream_msgs: Arc<Mutex<Vec<AddStreamMsg>>>,
        _listen_results: Vec<Box<dyn ListenerHandler<Item = (), Error = ()>>>,
    }

    impl ListenerHandler for ListenerHandlerNull {
        fn bind_port_and_configuration(
            &mut self,
            port: u16,
            discriminator_factories: PortConfiguration,
        ) -> io::Result<()> {
            self.log.lock().unwrap().log(format!(
                "bind_port_and_configuration ({}, PortConfiguration {{is_clandestine: {}, ...}})",
                port, discriminator_factories.is_clandestine
            ));
            self.port_configuration_parameter = Some(discriminator_factories);
            self.bind_port_and_discriminator_factories_result
                .take()
                .unwrap()
        }

        fn bind_subs(&mut self, add_stream_sub: Recipient<AddStreamMsg>) {
            let logger = Logger::new("ListenerHandler");
            error!(logger, String::from("bind_subscribers (add_stream_sub)"));

            self.add_stream_sub = Some(add_stream_sub);
        }
    }

    impl Future for ListenerHandlerNull {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
            self.log.lock().unwrap().log(String::from("poll (...)"));
            let mut add_stream_msgs = self.add_stream_msgs.lock().unwrap();
            let add_stream_sub = self.add_stream_sub.as_ref().unwrap();
            while add_stream_msgs.len() > 0 {
                let add_stream_msg = add_stream_msgs.remove(0);
                add_stream_sub
                    .try_send(add_stream_msg)
                    .expect("StreamHandlerPool is dead");
            }
            Ok(Async::NotReady)
        }
    }

    impl TestLogOwner for ListenerHandlerNull {
        fn get_test_log(&self) -> Arc<Mutex<TestLog>> {
            self.log.clone()
        }
    }

    impl ListenerHandlerNull {
        fn new(add_stream_msgs: Vec<AddStreamMsg>) -> ListenerHandlerNull {
            ListenerHandlerNull {
                log: Arc::new(Mutex::new(TestLog::new())),
                bind_port_and_discriminator_factories_result: None,
                port_configuration_parameter: None,
                add_stream_sub: None,
                add_stream_msgs: Arc::new(Mutex::new(add_stream_msgs)),
                _listen_results: vec![],
            }
        }

        fn bind_port_result(mut self, result: io::Result<()>) -> ListenerHandlerNull {
            self.bind_port_and_discriminator_factories_result = Some(result);
            self
        }
    }

    fn make_default_cli_params() -> Vec<String> {
        vec![
            String::from("SubstratumNode"),
            String::from("--dns-servers"),
            String::from("222.222.222.222"),
        ]
    }

    #[test]
    fn knows_its_name() {
        let subject = BootstrapperBuilder::new().build();

        let result = subject.name();

        assert_eq!(result, String::from("Dispatcher"));
    }

    #[test]
    fn initialize_as_privileged_with_no_args_binds_http_and_tls_ports() {
        let _lock = INITIALIZATION.lock();
        let (first_handler, first_handler_log) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let (second_handler, second_handler_log) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let (third_handler, third_handler_log) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(first_handler))
            .add_listener_handler(Box::new(second_handler))
            .add_listener_handler(Box::new(third_handler))
            .build();

        subject.initialize_as_privileged(
            &make_default_cli_params(),
            &mut FakeStreamHolder::new().streams(),
        );

        let mut all_calls = vec![];
        all_calls.extend(first_handler_log.lock().unwrap().dump());
        all_calls.extend(second_handler_log.lock().unwrap().dump());
        all_calls.extend(third_handler_log.lock().unwrap().dump());
        assert!(
            all_calls.contains(&String::from(
                "bind_port_and_configuration (80, PortConfiguration {is_clandestine: false, ...})"
            )),
            "{:?}",
            all_calls
        );
        assert!(
            all_calls.contains(&String::from(
                "bind_port_and_configuration (443, PortConfiguration {is_clandestine: false, ...})"
            )),
            "{:?}",
            all_calls
        );
        assert_eq!(all_calls.len(), 2, "{:?}", all_calls);
    }

    #[test]
    fn initialize_as_privileged_with_no_args_produces_empty_clandestine_discriminator_factories_vector(
    ) {
        let _lock = INITIALIZATION.lock();
        let first_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let second_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(first_handler)
            .add_listener_handler(second_handler)
            .build();

        subject.initialize_as_privileged(
            &vec!["SubstratumNode".to_string()],
            &mut FakeStreamHolder::new().streams(),
        );

        let config = subject.config;
        assert_eq!(
            config.neighborhood_config.clandestine_port_list.is_empty(),
            true
        );
        assert_eq!(config.clandestine_discriminator_factories.is_empty(), true);
    }

    #[test]
    fn initialize_as_unprivileged_passes_node_descriptor_to_ui_config() {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_unprivileged_passes_node_descriptor_to_ui_config",
        );
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        config.data_directory = data_dir.clone();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .config(config)
            .build();

        subject.initialize_as_unprivileged(
            &vec![
                "SubstratumNode".to_string(),
                String::from("--data-directory"),
                data_dir.to_str().unwrap().to_string(),
            ],
            &mut FakeStreamHolder::new().streams(),
        );

        let config = subject.config;
        assert!(!config.ui_gateway_config.node_descriptor.is_empty());
    }

    #[test]
    fn initialize_with_clandestine_port_produces_expected_clandestine_discriminator_factories_vector(
    ) {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_with_clandestine_port_produces_expected_clandestine_discriminator_factories_vector",
        );
        let first_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let second_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let third_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(first_handler)
            .add_listener_handler(second_handler)
            .add_listener_handler(third_handler)
            .build();
        let args = &vec![
            String::from("SubstratumNode"),
            String::from("--dns-servers"),
            String::from("222.222.222.222"),
            String::from("--clandestine-port"),
            String::from("1234"),
            String::from("--data-directory"),
            data_dir.to_str().unwrap().to_string(),
        ];
        let mut holder = FakeStreamHolder::new();

        subject.initialize_as_privileged(&args, &mut holder.streams());
        subject.initialize_as_unprivileged(&args, &mut holder.streams());

        let config = subject.config;
        assert!(config.neighborhood_config.clandestine_port_list.is_empty());
        assert_eq!(config.clandestine_port_opt, Some(1234u16));
    }

    #[test]
    fn init_as_privileged_stores_dns_servers_and_passes_them_to_actor_system_factory_for_proxy_client_in_init_as_unprivileged(
    ) {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "init_as_privileged_stores_dns_servers_and_passes_them_to_actor_system_factory_for_proxy_client_in_init_as_unprivileged",
        );
        let args = &vec![
            String::from("SubstratumNode"),
            String::from("--dns-servers"),
            String::from("1.2.3.4,2.3.4.5"),
            String::from("--clandestine-port"),
            String::from("1234"),
            String::from("--data-directory"),
            data_dir.to_str().unwrap().to_string(),
        ];
        let mut holder = FakeStreamHolder::new();
        let actor_system_factory = ActorSystemFactoryMock::new();
        let dns_servers_arc = actor_system_factory.dnss.clone();
        let mut subject = BootstrapperBuilder::new()
            .actor_system_factory(Box::new(actor_system_factory))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .build();

        subject.initialize_as_privileged(&args, &mut holder.streams());
        subject.initialize_as_unprivileged(&args, &mut holder.streams());

        let dns_servers_guard = dns_servers_arc.lock().unwrap();
        assert_eq!(
            dns_servers_guard.as_ref().unwrap(),
            &vec!(
                SocketAddr::from_str("1.2.3.4:53").unwrap(),
                SocketAddr::from_str("2.3.4.5:53").unwrap()
            )
        )
    }

    #[test]
    #[should_panic(expected = "Could not listen on port")]
    fn initialize_as_privileged_panics_if_tcp_listener_doesnt_bind() {
        let _lock = INITIALIZATION.lock();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![])
                    .bind_port_result(Err(io::Error::from(ErrorKind::AddrInUse))),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .build();

        subject.initialize_as_privileged(
            &vec![
                String::from("SubstratumNode"),
                String::from("--dns-servers"),
                String::from("1.1.1.1"),
            ],
            &mut FakeStreamHolder::new().streams(),
        );
    }

    #[test]
    fn initialize_cryptde_without_cryptde_null_uses_cryptde_real() {
        let cryptde_init = Bootstrapper::initialize_cryptde(&None, DEFAULT_CHAIN_ID);

        assert_eq!(cryptde_ref().public_key(), cryptde_init.public_key());
        // Brittle assertion: this may not be true forever
        let cryptde_null = cryptde();
        assert!(cryptde_init.public_key().len() > cryptde_null.public_key().len());
    }

    #[test]
    fn initialize_cryptde_with_cryptde_null_uses_cryptde_null() {
        let cryptde_null = cryptde().clone();
        let cryptde_null_public_key = cryptde_null.public_key().clone();

        let cryptde = Bootstrapper::initialize_cryptde(&Some(cryptde_null), DEFAULT_CHAIN_ID);

        assert_eq!(cryptde.public_key(), &cryptde_null_public_key);
        assert_eq!(cryptde_ref().public_key(), cryptde.public_key());
    }

    #[test]
    fn initialize_cryptde_and_report_local_descriptor() {
        let _lock = INITIALIZATION.lock();
        init_test_logging();
        let ip_addr = IpAddr::from_str("2.3.4.5").unwrap();
        let ports = vec![3456u16, 4567u16];
        let mut holder = FakeStreamHolder::new();
        let cryptde_ref = {
            let mut streams = holder.streams();

            let cryptde_ref = Bootstrapper::initialize_cryptde(&None, DEFAULT_CHAIN_ID);
            Bootstrapper::report_local_descriptor(cryptde_ref, ip_addr, ports, &mut streams);

            cryptde_ref
        };
        let stdout_dump = holder.stdout.get_string();
        let expected_descriptor = format!(
            "{}:2.3.4.5:3456,4567",
            cryptde_ref.public_key_to_descriptor_fragment(cryptde_ref.public_key())
        );
        let regex = Regex::new(r"SubstratumNode local descriptor: (.+?)\n").unwrap();
        let captured_descriptor = regex
            .captures(stdout_dump.as_str())
            .unwrap()
            .get(1)
            .unwrap()
            .as_str();
        assert_eq!(captured_descriptor, expected_descriptor);
        TestLogHandler::new().exists_log_containing(
            format!(
                "INFO: Bootstrapper: SubstratumNode local descriptor: {}",
                expected_descriptor
            )
            .as_str(),
        );

        let expected_data = PlainData::new(b"ho'q ;iaerh;frjhvs;lkjerre");
        let crypt_data = cryptde_ref
            .encode(&cryptde_ref.public_key(), &expected_data)
            .unwrap();
        let decrypted_data = cryptde_ref.decode(&crypt_data).unwrap();
        assert_eq!(decrypted_data, expected_data)
    }

    #[test]
    fn initialize_as_unprivileged_binds_clandestine_port() {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_unprivileged_binds_clandestine_port",
        );
        let (one_listener_handler, _) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let (another_listener_handler, _) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let (clandestine_listener_handler, clandestine_listener_handler_log_arc) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(one_listener_handler))
            .add_listener_handler(Box::new(another_listener_handler))
            .add_listener_handler(Box::new(clandestine_listener_handler))
            .build();
        let mut holder = FakeStreamHolder::new();

        subject.initialize_as_privileged(
            &vec![
                "SubstratumNode".to_string(),
                "--dns-servers".to_string(),
                "1.1.1.1".to_string(),
                "--ip".to_string(),
                "1.2.3.4".to_string(),
                "--data-directory".to_string(),
                data_dir.display().to_string(),
            ],
            &mut holder.streams(),
        );
        subject.initialize_as_unprivileged(
            &vec![
                "SubstratumNode".to_string(),
                "--clandestine-port".to_string(),
                "1234".to_string(),
                String::from("--data-directory"),
                data_dir.display().to_string(),
            ],
            &mut holder.streams(),
        );

        let calls = clandestine_listener_handler_log_arc.lock().unwrap().dump();
        assert_eq!(
            calls,
            vec![
                "bind_port_and_configuration (1234, PortConfiguration {is_clandestine: true, ...})"
                    .to_string()
            ],
        );
    }

    #[test]
    fn initialize_as_unprivileged_moves_streams_from_listener_handlers_to_stream_handler_pool() {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists("bootstrapper", "initialize_as_unprivileged_moves_streams_from_listener_handlers_to_stream_handler_pool");
        init_test_logging();
        let args = vec![
            "SubstratumNode".to_string(),
            String::from("--data-directory"),
            data_dir.to_str().unwrap().to_string(),
        ];
        let mut holder = FakeStreamHolder::new();
        let one_listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let another_listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let yet_another_listener_handler =
            ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let actor_system_factory = ActorSystemFactoryMock::new();
        let mut config = BootstrapperConfig::new();
        config.data_directory = data_dir;
        let mut subject = BootstrapperBuilder::new()
            .actor_system_factory(Box::new(actor_system_factory))
            .add_listener_handler(Box::new(one_listener_handler))
            .add_listener_handler(Box::new(another_listener_handler))
            .add_listener_handler(Box::new(yet_another_listener_handler))
            .config(config)
            .build();
        subject.initialize_as_privileged(&args, &mut holder.streams());

        subject.initialize_as_unprivileged(&args, &mut holder.streams());

        // Checking log message cause I don't know how to get at add_stream_sub
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec![
            "bind_subscribers (add_stream_sub)",
            "bind_subscribers (add_stream_sub)",
        ]);
    }

    #[test]
    fn bootstrapper_as_future_polls_listener_handler_futures() {
        let _lock = INITIALIZATION.lock();
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "bootstrapper_as_future_polls_listener_handler_futures",
        );
        let mut holder = FakeStreamHolder::new();
        let connection_info1 = ConnectionInfo {
            reader: Box::new(ReadHalfWrapperMock::new()),
            writer: Box::new(WriteHalfWrapperMock::new()),
            local_addr: SocketAddr::from_str("1.1.1.1:80").unwrap(),
            peer_addr: SocketAddr::from_str("1.1.1.1:40").unwrap(),
        };
        let connection_info2 = ConnectionInfo {
            reader: Box::new(ReadHalfWrapperMock::new()),
            writer: Box::new(WriteHalfWrapperMock::new()),
            local_addr: SocketAddr::from_str("2.2.2.2:80").unwrap(),
            peer_addr: SocketAddr::from_str("2.2.2.2:40").unwrap(),
        };
        let connection_info3 = ConnectionInfo {
            reader: Box::new(ReadHalfWrapperMock::new()),
            writer: Box::new(WriteHalfWrapperMock::new()),
            local_addr: SocketAddr::from_str("3.3.3.3:80").unwrap(),
            peer_addr: SocketAddr::from_str("3.3.3.3:40").unwrap(),
        };
        let first_message = AddStreamMsg {
            connection_info: connection_info1,
            origin_port: Some(80),
            port_configuration: PortConfiguration::new(vec![], false),
        };
        let second_message = AddStreamMsg {
            connection_info: connection_info2,
            origin_port: None,
            port_configuration: PortConfiguration::new(vec![], false),
        };
        let third_message = AddStreamMsg {
            connection_info: connection_info3,
            origin_port: Some(443),
            port_configuration: PortConfiguration::new(vec![], false),
        };
        let one_listener_handler =
            ListenerHandlerNull::new(vec![first_message, second_message]).bind_port_result(Ok(()));
        let another_listener_handler =
            ListenerHandlerNull::new(vec![third_message]).bind_port_result(Ok(()));
        let mut actor_system_factory = ActorSystemFactoryMock::new();
        let awaiter = actor_system_factory
            .stream_handler_pool_cluster
            .awaiter
            .take()
            .unwrap();
        let recording_arc = actor_system_factory
            .stream_handler_pool_cluster
            .recording
            .take()
            .unwrap();
        let mut subject = BootstrapperBuilder::new()
            .actor_system_factory(Box::new(actor_system_factory))
            .add_listener_handler(Box::new(one_listener_handler))
            .add_listener_handler(Box::new(another_listener_handler))
            .build();
        let args = vec![
            String::from("SubstratumNode"),
            String::from("--dns-servers"),
            String::from("222.222.222.222"),
            String::from("--data-directory"),
            data_dir.to_str().unwrap().to_string(),
        ];

        subject.initialize_as_privileged(&args, &mut holder.streams());
        subject.initialize_as_unprivileged(&args, &mut holder.streams());

        thread::spawn(|| {
            tokio::run(subject);
        });

        let number_of_expected_messages = 3;
        awaiter.await_message_count(number_of_expected_messages);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), number_of_expected_messages);
        let actual_ports: Vec<String> = (0..number_of_expected_messages)
            .map(|i| {
                let record = recording.get_record::<AddStreamMsg>(i);
                format!("{:?}", record.origin_port)
            })
            .collect();
        assert_contains(&actual_ports, &String::from("Some(80)"));
        assert_contains(&actual_ports, &String::from("None"));
        assert_contains(&actual_ports, &String::from("Some(443)"));
    }

    #[test]
    fn establish_clandestine_port_handles_specified_port() {
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "establish_clandestine_port_handles_specified_port",
        );
        let cryptde = CryptDENull::from(&PublicKey::new(&[1, 2, 3, 4]), DEFAULT_CHAIN_ID);
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config.local_ip_addr = IpAddr::from_str("1.2.3.4").unwrap(); // not sentinel
        config.neighborhood_config.neighbor_configs = vec![NodeDescriptor {
            public_key: cryptde.public_key().clone(),
            node_addr: NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![1234]),
        }
        .to_string(&cryptde)];
        config.data_directory = data_dir.clone();
        config.clandestine_port_opt = Some(1234);
        let listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .config(config)
            .build();

        subject.establish_clandestine_port();

        let conn = DbInitializerReal::new().initialize(&data_dir).unwrap();
        let config_dao = ConfigDaoReal::new(conn);
        let persistent_config = PersistentConfigurationReal::new(Box::new(config_dao));
        assert_eq!(1234u16, persistent_config.clandestine_port());
        assert_eq!(
            vec![1234u16],
            subject.config.neighborhood_config.clandestine_port_list
        );
        assert_eq!(1, subject.listener_handlers.len());

        let config = subject.config;
        let mut clandestine_discriminators = config
            .clandestine_discriminator_factories
            .into_iter()
            .map(|factory| factory.make())
            .collect::<Vec<Discriminator>>();
        let mut discriminator = clandestine_discriminators.remove(0);
        discriminator.add_data(&b"{\"component\": \"NBHD\", \"bodyText\": \"Booga\"}"[..]);
        assert_eq!(
            Some(UnmaskedChunk {
                chunk: b"Booga".to_vec(),
                last_chunk: true,
                sequenced: false,
            }),
            discriminator.take_chunk(),
        );
        assert_eq!(0, clandestine_discriminators.len()); // Used to be 1, now 0 after removal
    }

    #[test]
    fn establish_clandestine_port_handles_unspecified_port() {
        let cryptde = CryptDENull::from(&PublicKey::new(&[1, 2, 3, 4]), DEFAULT_CHAIN_ID);
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "establish_clandestine_port_handles_unspecified_port",
        );
        let mut config = BootstrapperConfig::new();
        config.neighborhood_config.local_ip_addr = IpAddr::from_str("1.2.3.4").unwrap(); // not sentinel
        config.neighborhood_config.neighbor_configs = vec![NodeDescriptor {
            public_key: cryptde.public_key().clone(),
            node_addr: NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![1234]),
        }
        .to_string(&cryptde)];
        config.data_directory = data_dir.clone();
        config.clandestine_port_opt = None;
        let listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .config(config)
            .build();

        subject.establish_clandestine_port();

        let conn = DbInitializerReal::new().initialize(&data_dir).unwrap();
        let config_dao = ConfigDaoReal::new(conn);
        let persistent_config = PersistentConfigurationReal::new(Box::new(config_dao));
        let clandestine_port = persistent_config.clandestine_port();
        assert_eq!(
            vec![clandestine_port],
            subject.config.neighborhood_config.clandestine_port_list
        );
    }

    #[test]
    fn establish_clandestine_port_handles_zero_hop() {
        let data_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "establish_clandestine_port_handles_zero_hop",
        );
        let mut config = BootstrapperConfig::new();
        config.data_directory = data_dir.clone();
        config.clandestine_port_opt = None;
        config.neighborhood_config.neighbor_configs = vec![]; // empty
        config.neighborhood_config.local_ip_addr = sentinel_ip_addr(); // sentinel
        config.neighborhood_config.clandestine_port_list = vec![];
        let listener_handler = ListenerHandlerNull::new(vec![]);
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .config(config)
            .build();

        subject.establish_clandestine_port();

        assert!(subject
            .config
            .neighborhood_config
            .clandestine_port_list
            .is_empty());
    }

    struct StreamHandlerPoolCluster {
        recording: Option<Arc<Mutex<Recording>>>,
        awaiter: Option<RecordAwaiter>,
        subs: StreamHandlerPoolSubs,
    }

    struct ActorSystemFactoryMock {
        stream_handler_pool_cluster: StreamHandlerPoolCluster,
        dnss: Arc<Mutex<Option<Vec<SocketAddr>>>>,
    }

    impl ActorSystemFactory for ActorSystemFactoryMock {
        fn make_and_start_actors(
            &self,
            config: BootstrapperConfig,
            _actor_factory: Box<dyn ActorFactory>,
        ) -> StreamHandlerPoolSubs {
            let mut parameter_guard = self.dnss.lock().unwrap();
            let parameter_ref = parameter_guard.deref_mut();
            *parameter_ref = Some(config.dns_servers);

            self.stream_handler_pool_cluster.subs.clone()
        }
    }

    impl ActorSystemFactoryMock {
        fn new() -> ActorSystemFactoryMock {
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let system = System::new("test");

                let stream_handler_pool_cluster = {
                    let (stream_handler_pool, awaiter, recording) = make_recorder();
                    StreamHandlerPoolCluster {
                        recording: Some(recording),
                        awaiter: Some(awaiter),
                        subs: make_stream_handler_pool_subs_from(Some(stream_handler_pool)),
                    }
                };

                tx.send(stream_handler_pool_cluster).unwrap();
                system.run();
            });
            let stream_handler_pool_cluster = rx.recv().unwrap();
            ActorSystemFactoryMock {
                stream_handler_pool_cluster,
                dnss: Arc::new(Mutex::new(None)),
            }
        }
    }

    struct BootstrapperBuilder {
        actor_system_factory: Box<dyn ActorSystemFactory>,
        log_initializer_wrapper: Box<dyn LoggerInitializerWrapper>,
        listener_handler_factory: ListenerHandlerFactoryMock,
        config: BootstrapperConfig,
    }

    impl BootstrapperBuilder {
        fn new() -> BootstrapperBuilder {
            BootstrapperBuilder {
                actor_system_factory: Box::new(ActorSystemFactoryMock::new()),
                log_initializer_wrapper: Box::new(LoggerInitializerWrapperMock::new()),
                // Don't modify this line unless you've already looked at DispatcherBuilder::add_listener_handler().
                listener_handler_factory: ListenerHandlerFactoryMock::new(),
                config: BootstrapperConfig::new(),
            }
        }

        fn actor_system_factory(
            mut self,
            actor_system_factory: Box<dyn ActorSystemFactory>,
        ) -> BootstrapperBuilder {
            self.actor_system_factory = actor_system_factory;
            self
        }

        fn add_listener_handler(
            mut self,
            listener_handler: Box<dyn ListenerHandler<Item = (), Error = ()>>,
        ) -> BootstrapperBuilder {
            self.listener_handler_factory.add(listener_handler);
            self
        }

        fn config(mut self, config: BootstrapperConfig) -> Self {
            self.config = config;
            self
        }

        fn build(self) -> Bootstrapper {
            Bootstrapper {
                actor_system_factory: self.actor_system_factory,
                listener_handler_factory: Box::new(self.listener_handler_factory),
                listener_handlers: FuturesUnordered::<
                    Box<dyn ListenerHandler<Item = (), Error = ()>>,
                >::new(),
                logger_initializer: self.log_initializer_wrapper,
                config: self.config,
            }
        }
    }
}
