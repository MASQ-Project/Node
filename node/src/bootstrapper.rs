// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::accountant::DEFAULT_PAYABLE_SCAN_INTERVAL;
use crate::actor_system_factory::ActorFactoryReal;
use crate::actor_system_factory::ActorSystemFactory;
use crate::actor_system_factory::ActorSystemFactoryReal;
use crate::blockchain::blockchain_interface::TESTNET_CONTRACT_ADDRESS;
use crate::config_dao::ConfigDaoReal;
use crate::configuration::{Configuration, PortConfiguration};
use crate::crash_test_dummy::CrashTestDummy;
use crate::database::db_initializer::{DbInitializer, DbInitializerReal};
use crate::discriminator::DiscriminatorFactory;
use crate::json_discriminator_factory::JsonDiscriminatorFactory;
use crate::listener_handler::ListenerHandler;
use crate::listener_handler::ListenerHandlerFactory;
use crate::listener_handler::ListenerHandlerFactoryReal;
use crate::persistent_configuration::{
    PersistentConfiguration, PersistentConfigurationReal, LOWEST_USABLE_INSECURE_PORT,
};
use crate::server_initializer::LoggerInitializerWrapper;
use crate::sub_lib::accountant;
use crate::sub_lib::accountant::AccountantConfig;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
use crate::sub_lib::crash_point::CrashPoint;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::neighborhood::NeighborhoodConfig;
use crate::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use crate::sub_lib::neighborhood::{sentinel_ip_addr, NodeDescriptor};
use crate::sub_lib::socket_server::SocketServer;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
use crate::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use crate::sub_lib::wallet::Wallet;
use base64;
use clap::{
    arg_enum, crate_authors, crate_description, crate_version, value_t, values_t, App, Arg,
};
use dirs::data_dir;
use futures::try_ready;
use log::LevelFilter;
use regex::Regex;
use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::vec::Vec;
use tokio::prelude::stream::futures_unordered::FuturesUnordered;
use tokio::prelude::Async;
use tokio::prelude::Future;
use tokio::prelude::Stream;

pub static mut CRYPT_DE_OPT: Option<CryptDENull> = None;

arg_enum! {
    #[derive(Debug, PartialEq, Clone)]
    enum NodeType {
        Bootstrap,
        Standard
    }
}

impl Into<bool> for NodeType {
    fn into(self) -> bool {
        match self {
            NodeType::Bootstrap => true,
            NodeType::Standard => false,
        }
    }
}

#[derive(Clone)]
pub struct BootstrapperConfig {
    pub log_level: LevelFilter,
    pub dns_servers: Vec<SocketAddr>,
    pub neighborhood_config: NeighborhoodConfig,
    pub accountant_config: AccountantConfig,
    pub crash_point: CrashPoint,
    pub clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    pub ui_gateway_config: UiGatewayConfig,
    pub blockchain_bridge_config: BlockchainBridgeConfig,
    // This is to defer storing of the clandestine port in the database until after privilege is
    // relinquished, so that if we create the database we don't do it as root, which would lead
    // to an unfortunate ownership and privilege situation for the database file.
    pub clandestine_port_opt: Option<u16>,
    pub data_directory: PathBuf,
}

impl BootstrapperConfig {
    pub fn new() -> BootstrapperConfig {
        BootstrapperConfig {
            log_level: LevelFilter::Off,
            dns_servers: vec![],
            neighborhood_config: NeighborhoodConfig {
                neighbor_configs: vec![],
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                clandestine_port_list: vec![],
                earning_wallet: accountant::DEFAULT_EARNING_WALLET.clone(),
                consuming_wallet: None,
                rate_pack: DEFAULT_RATE_PACK.clone(),
            },
            accountant_config: AccountantConfig {
                payable_scan_interval: Duration::from_secs(DEFAULT_PAYABLE_SCAN_INTERVAL),
            },
            crash_point: CrashPoint::None,
            clandestine_discriminator_factories: vec![],
            ui_gateway_config: UiGatewayConfig {
                ui_port: DEFAULT_UI_PORT,
                node_descriptor: String::from(""),
            },
            blockchain_bridge_config: BlockchainBridgeConfig {
                blockchain_service_url: None,
                contract_address: TESTNET_CONTRACT_ADDRESS,
                consuming_private_key: None,
            },
            clandestine_port_opt: None,
            data_directory: PathBuf::new(),
        }
    }
}

// TODO: Consider splitting this into a piece that's meant for being root and a piece that's not.
pub struct Bootstrapper {
    listener_handler_factory: Box<dyn ListenerHandlerFactory>,
    listener_handlers: FuturesUnordered<Box<dyn ListenerHandler<Item = (), Error = ()>>>,
    actor_system_factory: Box<dyn ActorSystemFactory>,
    config: Option<BootstrapperConfig>,
}

impl Future for Bootstrapper {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        if let Some(ref bootstrap_config) = self.config {
            try_ready!(CrashTestDummy::new(bootstrap_config.crash_point.clone()).poll());
        }

        try_ready!(self.listener_handlers.poll());
        Ok(Async::Ready(()))
    }
}

impl SocketServer for Bootstrapper {
    fn name(&self) -> String {
        String::from("Dispatcher")
    }

    fn initialize_as_privileged(
        &mut self,
        args: &Vec<String>,
        logger_initializer: &mut Box<dyn LoggerInitializerWrapper>,
    ) {
        let mut configuration = Configuration::new();
        configuration.establish();
        let mut config = BootstrapperConfig::new();
        Bootstrapper::parse_args(args, &mut config);
        logger_initializer.init(config.log_level);
        Bootstrapper::parse_environment_variables(&mut config);
        self.config = Some(config);
        self.listener_handlers =
            FuturesUnordered::<Box<dyn ListenerHandler<Item = (), Error = ()>>>::new();

        configuration
            .port_configurations
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

    fn initialize_as_unprivileged(&mut self, streams: &mut StdStreams<'_>) {
        // NOTE: The following line of code is not covered by unit tests
        fdlimit::raise_fd_limit();
        self.establish_clandestine_port();
        let cryptde_ref = Bootstrapper::initialize_cryptde();
        let config = self.config.as_mut().expect("Configuration missing");
        config.ui_gateway_config.node_descriptor = Bootstrapper::report_local_descriptor(
            cryptde_ref,
            config.neighborhood_config.local_ip_addr,
            config.neighborhood_config.clandestine_port_list.clone(),
            streams,
        );
        let stream_handler_pool_subs = self.actor_system_factory.make_and_start_actors(
            self.config
                .as_ref()
                .expect("Missing BootstrapperConfig - call initialize_as_privileged first")
                .clone(),
            Box::new(ActorFactoryReal {}),
        );
        let mut iter_mut = self.listener_handlers.iter_mut();
        loop {
            match iter_mut.next() {
                Some(f) => f.bind_subs(stream_handler_pool_subs.add_sub.clone()),
                None => break,
            }
        }
    }
}

impl Bootstrapper {
    pub fn new() -> Bootstrapper {
        Bootstrapper {
            listener_handler_factory: Box::new(ListenerHandlerFactoryReal::new()),
            listener_handlers:
                FuturesUnordered::<Box<dyn ListenerHandler<Item = (), Error = ()>>>::new(),
            actor_system_factory: Box::new(ActorSystemFactoryReal {}),
            config: None,
        }
    }

    fn parse_args(args: &Vec<String>, config: &mut BootstrapperConfig) {
        let default_ui_port_value = DEFAULT_UI_PORT.to_string();
        let default_earning_wallet_value = accountant::DEFAULT_EARNING_WALLET.clone().address;
        let default_crash_point_value = format!("{}", CrashPoint::None);
        let default_node_type_value = format!("{}", NodeType::Standard);
        let default_ip_value = sentinel_ip_addr().to_string();
        let default_data_dir_value = Bootstrapper::data_directory_default(&RealDirsWrapper {});
        let matches = App::new("SubstratumNode")
            .version(crate_version!())
            .author(crate_authors!("\n"))
            .about(crate_description!())
            .arg(
                Arg::with_name("blockchain_service_url")
                    .long("blockchain_service_url")
                    .value_name("URL")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("clandestine_port")
                    .long("clandestine_port")
                    .value_name("CLANDESTINE_PORT")
                    .empty_values(false)
                    .validator(Bootstrapper::validate_clandestine_port)
                    .help("Must be between 1025 and 65535 [default: last used port]"),
            )
            .arg(
                Arg::with_name("data_directory")
                    .long("data_directory")
                    .value_name("DATA_DIRECTORY")
                    .empty_values(false)
                    .default_value(&default_data_dir_value),
            )
            .arg(
                Arg::with_name("dns_servers")
                    .long("dns_servers")
                    .value_name("DNS_SERVERS")
                    .takes_value(true)
                    .required(true)
                    .use_delimiter(true)
                    .validator(Bootstrapper::validate_ip_address),
            )
            .arg(
                Arg::with_name("ip")
                    .long("ip")
                    .value_name("IP")
                    .takes_value(true)
                    .default_value(&default_ip_value)
                    .validator(Bootstrapper::validate_ip_address),
            )
            .arg(
                Arg::with_name("log_level")
                    .long("log_level")
                    .value_name("FILTER")
                    .takes_value(true)
                    .possible_values(&["error", "warn", "info", "debug", "trace", "off"])
                    .default_value("warn")
                    .case_insensitive(true),
            )
            .arg(
                Arg::with_name("neighbor")
                    .long("neighbor")
                    .value_name("NODE_DESCRIPTOR")
                    .takes_value(true)
                    .number_of_values(1)
                    .multiple(true)
                    .requires("ip")
                    .validator(|s| NodeDescriptor::from_str(&s).map(|_| ())),
            )
            .arg(
                Arg::with_name("node_type")
                    .long("node_type")
                    .value_name("NODE_TYPE")
                    .takes_value(true)
                    .possible_values(&NodeType::variants())
                    .default_value(&default_node_type_value)
                    .case_insensitive(true),
            )
            .arg(
                Arg::with_name("ui_port")
                    .long("ui_port")
                    .value_name("UI_PORT")
                    .takes_value(true)
                    .default_value(&default_ui_port_value)
                    .validator(Bootstrapper::validate_ui_port)
                    .help(&format!(
                        "Must be between 1025 and 65535; defaults to {}",
                        DEFAULT_UI_PORT
                    )),
            )
            .arg(
                Arg::with_name("wallet_address")
                    .long("wallet_address")
                    .value_name("WALLET_ADDRESS")
                    .takes_value(true)
                    .default_value(&default_earning_wallet_value)
                    .hide_default_value(true)
                    .validator(Bootstrapper::validate_ethereum_address)
                    .help(&format!(
                        "Must be 42 characters long, contain only hex and start with 0x"
                    )),
            )
            .arg(
                Arg::with_name("crash_point")
                    .long("crash_point")
                    .value_name("CRASH_POINT")
                    .takes_value(true)
                    .default_value(&default_crash_point_value)
                    .possible_values(&CrashPoint::variants())
                    .case_insensitive(true)
                    .hidden(true)
                    .help("Only used for testing"),
            )
            .get_matches_from(args.iter());

        config.blockchain_bridge_config.blockchain_service_url = matches
            .value_of("blockchain_service_url")
            .map(|s| String::from(s));

        config.clandestine_port_opt = match value_t!(matches, "clandestine_port", u16) {
            Ok(port) => Some(port),
            Err(_) => None,
        };

        config.data_directory =
            value_t!(matches, "data_directory", PathBuf).expect("Internal Error");

        config.dns_servers = matches
            .values_of("dns_servers")
            .expect("Internal Error")
            .into_iter()
            .map(|s| SocketAddr::from((IpAddr::from_str(s).expect("Internal Error"), 53)))
            .collect();

        config.neighborhood_config.local_ip_addr =
            value_t!(matches, "ip", IpAddr).expect("Internal Error");

        config.log_level = value_t!(matches, "log_level", LevelFilter).expect("Internal Error");

        config.neighborhood_config.neighbor_configs =
            match values_t!(matches, "neighbor", NodeDescriptor) {
                Ok(neighbors) => neighbors,
                Err(_) => vec![],
            };

        config.neighborhood_config.is_bootstrap_node = value_t!(matches, "node_type", NodeType)
            .expect("Internal Error")
            .into();

        config.ui_gateway_config.ui_port =
            value_t!(matches, "ui_port", u16).expect("Internal Error");

        config.neighborhood_config.earning_wallet = Wallet::new(
            value_t!(matches, "wallet_address", String)
                .expect("Internal Error")
                .as_str(),
        );

        config.crash_point = value_t!(matches, "crash_point", CrashPoint).expect("Internal Error");

        // TODO: In real life this should come from a command-line parameter
        config.neighborhood_config.consuming_wallet =
            Some(accountant::TEMPORARY_CONSUMING_WALLET.clone());
    }

    fn parse_environment_variables(config: &mut BootstrapperConfig) {
        config.blockchain_bridge_config.consuming_private_key =
            match env::var("CONSUMING_PRIVATE_KEY") {
                Ok(key) => Bootstrapper::parse_private_key(key),
                Err(_) => None,
            };

        env::remove_var("CONSUMING_PRIVATE_KEY");
    }

    fn is_valid_private_key(key: &str) -> bool {
        Regex::new("^[0-9a-fA-F]{64}$")
            .expect("Failed to compile regular expression")
            .is_match(key)
    }

    fn parse_private_key(key: String) -> Option<String> {
        if !Bootstrapper::is_valid_private_key(&key) {
            panic!("CONSUMING_PRIVATE_KEY requires a valid Ethereum private key");
        }
        Some(key)
    }

    fn validate_ethereum_address(address: String) -> Result<(), String> {
        match Regex::new("^0x[0-9a-fA-F]{40}$")
            .expect("Failed to compile regular expression")
            .is_match(&address)
        {
            true => Ok(()),
            false => Err(address),
        }
    }

    fn validate_ip_address(address: String) -> Result<(), String> {
        match IpAddr::from_str(&address) {
            Ok(_) => Ok(()),
            Err(_) => Err(address),
        }
    }

    fn validate_ui_port(port: String) -> Result<(), String> {
        match str::parse::<u16>(&port) {
            Ok(port_number) if port_number < LOWEST_USABLE_INSECURE_PORT => Err(port),
            Ok(_) => Ok(()),
            Err(_) => Err(port),
        }
    }

    fn validate_clandestine_port(clandestine_port: String) -> Result<(), String> {
        match clandestine_port.parse::<u16>() {
            Ok(clandestine_port) if clandestine_port >= LOWEST_USABLE_INSECURE_PORT => Ok(()),
            _ => Err(clandestine_port),
        }
    }

    fn data_directory_default(dirs_wrapper: &DirsWrapper) -> String {
        dirs_wrapper
            .data_dir()
            .unwrap_or(PathBuf::from(""))
            .to_str()
            .expect("Internal Error")
            .to_string()
    }

    fn initialize_cryptde() -> &'static dyn CryptDE {
        let mut exemplar = CryptDENull::new();
        exemplar.generate_key_pair();
        let cryptde: &'static CryptDENull = unsafe {
            CRYPT_DE_OPT = Some(exemplar);
            CRYPT_DE_OPT.as_ref().expect("Internal error")
        };
        cryptde
    }

    fn report_local_descriptor(
        cryptde: &dyn CryptDE,
        ip_addr: IpAddr,
        ports: Vec<u16>,
        streams: &mut StdStreams<'_>,
    ) -> String {
        let port_strings: Vec<String> = ports.iter().map(|n| format!("{}", n)).collect();
        let port_list = port_strings.join(",");
        let encoded_public_key =
            base64::encode_config(&cryptde.public_key().as_slice(), base64::STANDARD_NO_PAD);
        let descriptor = format!("{}:{}:{}", &encoded_public_key, ip_addr, port_list);
        let descriptor_msg = format!("SubstratumNode local descriptor: {}", descriptor);
        writeln!(streams.stdout, "{}", descriptor_msg).expect("Internal error");
        Logger::new("Bootstrapper").info(descriptor_msg);
        descriptor
    }

    fn establish_clandestine_port(&mut self) {
        let mut config = self
            .config
            .as_mut()
            .expect("Configuration must be established");
        if Self::is_zero_hop(&config) {
            return;
        }
        let conn = DbInitializerReal::new()
            .initialize(&config.data_directory)
            .expect("Cannot initialize database");
        let config_dao = ConfigDaoReal::new(conn);
        let persistent_config = PersistentConfigurationReal::new(Box::new(config_dao));
        if let Some(clandestine_port) = config.clandestine_port_opt {
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
        config.neighborhood_config.clandestine_port_list = vec![clandestine_port];
        config
            .clandestine_discriminator_factories
            .push(Box::new(JsonDiscriminatorFactory::new()));
    }

    fn is_zero_hop(config: &BootstrapperConfig) -> bool {
        config.neighborhood_config.neighbor_configs.is_empty()
            && config.neighborhood_config.local_ip_addr == sentinel_ip_addr()
    }
}

struct RealDirsWrapper {}

trait DirsWrapper {
    fn data_dir(&self) -> Option<PathBuf>;
}

impl DirsWrapper for RealDirsWrapper {
    fn data_dir(&self) -> Option<PathBuf> {
        data_dir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor_system_factory::ActorFactory;
    use crate::config_dao::ConfigDaoReal;
    use crate::configuration::PortConfiguration;
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
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::sub_lib::stream_connector::ConnectionInfo;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLog;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::RecordAwaiter;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::test_utils::FakeStreamHolder;
    use crate::test_utils::test_utils::{assert_contains, ensure_node_home_directory_exists};
    use crate::test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use crate::test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use actix::Recipient;
    use actix::System;
    use lazy_static::lazy_static;
    use regex::Regex;
    use std::cell::RefCell;
    use std::env;
    use std::env::VarError;
    use std::ffi::OsStr;
    use std::io;
    use std::io::ErrorKind;
    use std::marker::Sync;
    use std::net::Ipv4Addr;
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
        static ref ENVIRONMENT: Mutex<Environment> = Mutex::new(Environment {});
        static ref INITIALIZATION: Mutex<bool> = Mutex::new(false);
    }

    struct Environment {}

    impl Environment {
        pub fn remove_var<K: AsRef<OsStr>>(&self, key: K) {
            env::remove_var(key);
        }

        pub fn set_var<K: AsRef<OsStr>, V: AsRef<OsStr>>(&self, key: K, value: V) {
            env::set_var(key, value);
        }

        pub fn var<K: AsRef<OsStr>>(&self, key: K) -> Result<String, VarError> {
            env::var(key)
        }
    }

    struct MockDirsWrapper {}

    impl DirsWrapper for MockDirsWrapper {
        fn data_dir(&self) -> Option<PathBuf> {
            Some(PathBuf::from("mocked/path"))
        }
    }

    struct BadMockDirsWrapper {}

    impl DirsWrapper for BadMockDirsWrapper {
        fn data_dir(&self) -> Option<PathBuf> {
            None
        }
    }

    struct ListenerHandlerFactoryMock {
        log: TestLog,
        mocks: RefCell<Vec<Box<dyn ListenerHandler<Item = (), Error = ()>>>>,
    }

    unsafe impl Sync for ListenerHandlerFactoryMock {}

    impl ListenerHandlerFactory for ListenerHandlerFactoryMock {
        fn make(&self) -> Box<dyn ListenerHandler<Item = (), Error = ()>> {
            self.log.log(format!("make ()"));
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
            logger.error(format!("bind_subscribers (add_stream_sub)"));

            self.add_stream_sub = Some(add_stream_sub);
        }
    }

    impl Future for ListenerHandlerNull {
        type Item = ();
        type Error = ();

        fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
            self.log.lock().unwrap().log(format!("poll (...)"));
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
            String::from("--dns_servers"),
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
    fn node_type_into() {
        let bootstrap: bool = NodeType::Bootstrap.into();
        let standard: bool = NodeType::Standard.into();

        assert_eq!(true, bootstrap);
        assert_eq!(false, standard);
    }

    #[test]
    fn parse_environment_variables_sets_consuming_private_key_to_none_when_not_specified() {
        let mut config = BootstrapperConfig::new();
        let environment = ENVIRONMENT.lock().unwrap();

        environment.remove_var("CONSUMING_PRIVATE_KEY");

        Bootstrapper::parse_environment_variables(&mut config);

        assert_eq!(config.blockchain_bridge_config.consuming_private_key, None);
    }

    #[test]
    fn parse_environment_variables_reads_consuming_private_key_when_specified() {
        let mut config = BootstrapperConfig::new();
        let environment = ENVIRONMENT.lock().unwrap();

        environment.set_var(
            "CONSUMING_PRIVATE_KEY",
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        );

        Bootstrapper::parse_environment_variables(&mut config);

        environment.remove_var("CONSUMING_PRIVATE_KEY");

        assert_eq!(
            config.blockchain_bridge_config.consuming_private_key,
            Some(String::from(
                "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9"
            ))
        );
    }

    #[test]
    #[should_panic(expected = "CONSUMING_PRIVATE_KEY requires a valid Ethereum private key")]
    fn parse_private_key_requires_a_key_that_is_64_characters_long() {
        Bootstrapper::parse_private_key(String::from("42"));
    }

    #[test]
    #[should_panic(expected = "CONSUMING_PRIVATE_KEY requires a valid Ethereum private key")]
    fn parse_private_key_must_contain_only_hex_characters() {
        Bootstrapper::parse_private_key(String::from(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cinvalidhex",
        ));
    }

    #[test]
    fn parse_private_key_handles_happy_path() {
        let result = Bootstrapper::parse_private_key(String::from(
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        ));

        assert_eq!(
            result,
            Some(String::from(
                "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9"
            ))
        );
    }

    #[test]
    fn validate_ip_address_given_invalid_input() {
        assert_eq!(
            Err(String::from("not-a-valid-IP")),
            Bootstrapper::validate_ip_address(String::from("not-a-valid-IP")),
        );
    }

    #[test]
    fn validate_ip_address_given_valid_input() {
        assert_eq!(
            Ok(()),
            Bootstrapper::validate_ip_address(String::from("1.2.3.4"))
        );
    }

    #[test]
    fn validate_ethereum_address_requires_an_address_that_is_42_characters_long() {
        assert_eq!(
            Err(String::from("my-favorite-wallet.com")),
            Bootstrapper::validate_ethereum_address(String::from("my-favorite-wallet.com")),
        );
    }

    #[test]
    fn validate_ethereum_address_must_start_with_0x() {
        assert_eq!(
            Err(String::from("x0my-favorite-wallet.com222222222222222222")),
            Bootstrapper::validate_ethereum_address(String::from(
                "x0my-favorite-wallet.com222222222222222222"
            ))
        );
    }

    #[test]
    fn validate_ethereum_address_must_contain_only_hex_characters() {
        assert_eq!(
            Err(String::from("0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q")),
            Bootstrapper::validate_ethereum_address(String::from(
                "0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q"
            ))
        );
    }

    #[test]
    fn validate_ethereum_address_when_happy() {
        assert_eq!(
            Ok(()),
            Bootstrapper::validate_ethereum_address(String::from(
                "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"
            ))
        );
    }

    #[test]
    fn parse_complains_about_non_numeric_ui_port() {
        let result = Bootstrapper::validate_ui_port(String::from("booga"));

        assert_eq!(Err(String::from("booga")), result);
    }

    #[test]
    fn parse_complains_about_ui_port_too_low() {
        let result = Bootstrapper::validate_ui_port(String::from("1023"));

        assert_eq!(Err(String::from("1023")), result);
    }

    #[test]
    fn parse_complains_about_ui_port_too_high() {
        let result = Bootstrapper::validate_ui_port(String::from("65536"));

        assert_eq!(Err(String::from("65536")), result);
    }

    #[test]
    fn parse_ui_port_works() {
        let result = Bootstrapper::validate_ui_port(String::from("5335"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn data_directory_default_given_no_default() {
        assert_eq!(
            String::from(""),
            Bootstrapper::data_directory_default(&BadMockDirsWrapper {})
        );
    }

    #[test]
    fn data_directory_default_works() {
        let mock_dirs_wrapper = MockDirsWrapper {};

        let result = Bootstrapper::data_directory_default(&mock_dirs_wrapper);

        assert_eq!(String::from("mocked/path"), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_badly_formatted_port_number() {
        let result = Bootstrapper::validate_clandestine_port(String::from("booga"));

        assert_eq!(Err(String::from("booga")), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_port_number_too_low() {
        let result = Bootstrapper::validate_clandestine_port(String::from("1024"));

        assert_eq!(Err(String::from("1024")), result);
    }

    #[test]
    fn validate_clandestine_port_rejects_port_number_too_high() {
        let result = Bootstrapper::validate_clandestine_port(String::from("65536"));

        assert_eq!(Err(String::from("65536")), result);
    }

    #[test]
    fn validate_clandestine_port_accepts_port_if_provided() {
        let result = Bootstrapper::validate_clandestine_port(String::from("4567"));

        assert_eq!(Ok(()), result);
    }

    #[test]
    fn parse_args_creates_configurations() {
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--dns_servers",
            "12.34.56.78,23.45.67.89",
            "--neighbor",
            "QmlsbA:1.2.3.4:1234,2345",
            "--ip",
            "34.56.78.90",
            "--clandestine_port",
            "1234",
            "--neighbor",
            "VGVk:2.3.4.5:3456,4567",
            "--node_type",
            "bootstrap",
            "--ui_port",
            "5335",
            "--wallet_address",
            "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF",
            "--data_directory",
            "~/.booga",
            "--blockchain_service_url",
            "http://127.0.0.1:8545",
            "--log_level",
            "trace",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let mut configuration = Configuration::new();

        configuration.establish();
        let mut config = BootstrapperConfig::new();
        Bootstrapper::parse_args(&args, &mut config);

        assert_eq!(
            vec!(
                SocketAddr::from_str("12.34.56.78:53").unwrap(),
                SocketAddr::from_str("23.45.67.89:53").unwrap()
            ),
            config.dns_servers,
        );
        assert_eq!(
            vec!(
                NodeDescriptor {
                    public_key: PublicKey::new(b"Bill"),
                    node_addr: NodeAddr::new(
                        &IpAddr::from_str("1.2.3.4").unwrap(),
                        &vec!(1234, 2345)
                    )
                },
                NodeDescriptor {
                    public_key: PublicKey::new(b"Ted"),
                    node_addr: NodeAddr::new(
                        &IpAddr::from_str("2.3.4.5").unwrap(),
                        &vec!(3456, 4567)
                    )
                }
            ),
            config.neighborhood_config.neighbor_configs,
        );
        assert_eq!(true, config.neighborhood_config.is_bootstrap_node);
        assert_eq!(
            IpAddr::V4(Ipv4Addr::new(34, 56, 78, 90)),
            config.neighborhood_config.local_ip_addr,
        );
        assert_eq!(config.ui_gateway_config.ui_port, 5335);
        assert_eq!(
            Wallet::new("0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"),
            config.neighborhood_config.earning_wallet,
        );
        let expected_port_list: Vec<u16> = vec![];
        assert_eq!(
            expected_port_list,
            config.neighborhood_config.clandestine_port_list
        );
        assert_eq!(
            Some("http://127.0.0.1:8545".to_string()),
            config.blockchain_bridge_config.blockchain_service_url
        );
        assert_eq!(PathBuf::from("~/.booga"), config.data_directory,);
        assert_eq!(Some(1234u16), config.clandestine_port_opt)
    }

    #[test]
    fn parse_args_creates_configuration_with_defaults() {
        let args: Vec<String> = vec!["SubstratumNode", "--dns_servers", "12.34.56.78,23.45.67.89"]
            .into_iter()
            .map(String::from)
            .collect();
        let mut configuration = Configuration::new();

        configuration.establish();
        let mut config = BootstrapperConfig::new();
        Bootstrapper::parse_args(&args, &mut config);

        assert_eq!(
            config.dns_servers,
            vec!(
                SocketAddr::from_str("12.34.56.78:53").unwrap(),
                SocketAddr::from_str("23.45.67.89:53").unwrap()
            )
        );
        assert_eq!(false, config.neighborhood_config.is_bootstrap_node);
        assert_eq!(None, config.clandestine_port_opt);
        assert_eq!(CrashPoint::None, config.crash_point);
        assert!(config.data_directory.is_dir());
        assert_eq!(
            Wallet::new("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            config.neighborhood_config.earning_wallet,
        );
        assert_eq!(sentinel_ip_addr(), config.neighborhood_config.local_ip_addr,);
        assert_eq!(5333, config.ui_gateway_config.ui_port);
    }

    #[test]
    fn parse_args_works_with_node_type_standard() {
        let args: Vec<String> = vec![
            "SubstratumNode",
            "--dns_servers",
            "12.34.56.78",
            "--node_type",
            "standard",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let mut config = BootstrapperConfig::new();

        Bootstrapper::parse_args(&args, &mut config);

        assert_eq!(config.neighborhood_config.is_bootstrap_node, false);
        assert_eq!(
            config.neighborhood_config.earning_wallet,
            accountant::DEFAULT_EARNING_WALLET.clone()
        );
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

        let mut log_initializer: Box<LoggerInitializerWrapper> =
            Box::new(LoggerInitializerWrapperMock::new());
        subject.initialize_as_privileged(&make_default_cli_params(), &mut log_initializer);

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
    fn initialize_as_privileged_reads_environment_variables() {
        let _lock = INITIALIZATION.lock();
        let environment = ENVIRONMENT.lock().unwrap();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .build();

        environment.set_var(
            "CONSUMING_PRIVATE_KEY",
            "9bc385849a4f9019a0acf7699da91422fdd0a3eb55ff4407e450f2c65e69a9f9",
        );

        let mut log_initializer: Box<LoggerInitializerWrapper> =
            Box::new(LoggerInitializerWrapperMock::new());
        subject.initialize_as_privileged(&make_default_cli_params(), &mut log_initializer);

        let config = subject.config.unwrap();
        assert_eq!(
            config.blockchain_bridge_config.consuming_private_key,
            Some("9bc385849a4f9019a0acf7699da91422fdd0a3eb55ff4407e450f2c65e69a9f9".to_string())
        );

        assert!(
            environment.var("CONSUMING_PRIVATE_KEY").is_err(),
            "CONSUMING_PRIVATE_KEY not cleared"
        );
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

        let mut log_initializer: Box<LoggerInitializerWrapper> =
            Box::new(LoggerInitializerWrapperMock::new());
        subject.initialize_as_privileged(&make_default_cli_params(), &mut log_initializer);

        let config = subject.config.unwrap();
        assert_eq!(
            config.neighborhood_config.clandestine_port_list.is_empty(),
            true
        );
        assert_eq!(config.clandestine_discriminator_factories.is_empty(), true);
    }

    #[test]
    fn initialize_as_unprivileged_passes_node_descriptor_to_ui_config() {
        let _lock = INITIALIZATION.lock();
        let home_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_unprivileged_passes_node_descriptor_to_ui_config",
        );
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .build();
        let mut config = BootstrapperConfig::new();
        config.clandestine_port_opt = Some(1234);
        config.data_directory = home_dir;
        subject.config = Some(config);

        subject.initialize_as_unprivileged(&mut FakeStreamHolder::new().streams());

        let config = subject.config.unwrap();
        assert!(config.ui_gateway_config.node_descriptor.len() > 0);
    }

    #[test]
    fn initialize_as_privileged_with_clandestine_port_produces_expected_clandestine_discriminator_factories_vector(
    ) {
        let _lock = INITIALIZATION.lock();
        let first_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let second_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let third_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(first_handler)
            .add_listener_handler(second_handler)
            .add_listener_handler(third_handler)
            .build();

        let mut log_initializer: Box<LoggerInitializerWrapper> =
            Box::new(LoggerInitializerWrapperMock::new());
        subject.initialize_as_privileged(
            &vec![
                String::from("SubstratumNode"),
                String::from("--dns_servers"),
                String::from("222.222.222.222"),
                String::from("--clandestine_port"),
                String::from("1234"),
            ],
            &mut log_initializer,
        );

        let config = subject.config.unwrap();
        assert!(config.neighborhood_config.clandestine_port_list.is_empty());
        assert_eq!(Some(1234u16), config.clandestine_port_opt);
    }

    #[test]
    fn initialize_as_privileged_stores_dns_servers_and_passes_them_to_actor_system_factory_for_proxy_client_in_initialize_as_unprivileged(
    ) {
        let _lock = INITIALIZATION.lock();
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

        let mut log_initializer: Box<LoggerInitializerWrapper> =
            Box::new(LoggerInitializerWrapperMock::new());
        subject.initialize_as_privileged(
            &vec![
                String::from("SubstratumNode"),
                String::from("--dns_servers"),
                String::from("1.2.3.4,2.3.4.5"),
                String::from("--clandestine_port"),
                String::from("1234"),
            ],
            &mut log_initializer,
        );

        subject.initialize_as_unprivileged(&mut holder.streams());

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

        let mut log_initializer: Box<LoggerInitializerWrapper> =
            Box::new(LoggerInitializerWrapperMock::new());
        subject.initialize_as_privileged(
            &vec![
                String::from("SubstratumNode"),
                String::from("--dns_servers"),
                String::from("1.1.1.1"),
            ],
            &mut log_initializer,
        );
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

            let cryptde_ref = Bootstrapper::initialize_cryptde();
            Bootstrapper::report_local_descriptor(cryptde_ref, ip_addr, ports, &mut streams);

            cryptde_ref
        };
        assert_ne!(cryptde_ref.private_key().as_slice(), &b"uninitialized"[..]);
        let stdout_dump = holder.stdout.get_string();
        let expected_descriptor = format!(
            "{}:2.3.4.5:3456,4567",
            base64::encode_config(
                &cryptde_ref.public_key().as_slice(),
                base64::STANDARD_NO_PAD,
            )
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
        let home_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "initialize_as_unprivileged_binds_clandestine_port",
        );
        let (listener_handler, listener_handler_log_arc) =
            extract_log(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .build();
        let mut config = BootstrapperConfig::new();
        config.data_directory = home_dir;
        config.clandestine_port_opt = Some(1234);
        subject.config = Some(config);

        subject.initialize_as_unprivileged(&mut FakeStreamHolder::new().streams());

        let calls = listener_handler_log_arc.lock().unwrap().dump();
        assert_eq!(
            vec![
                "bind_port_and_configuration (1234, PortConfiguration {is_clandestine: true, ...})"
                    .to_string()
            ],
            calls
        );
    }

    #[test]
    fn initialize_as_unprivileged_moves_streams_from_listener_handlers_to_stream_handler_pool() {
        let _lock = INITIALIZATION.lock();
        init_test_logging();
        let mut holder = FakeStreamHolder::new();
        let one_listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let another_listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let yet_another_listener_handler =
            ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let cli_params = vec![
            String::from("SubstratumNode"),
            String::from("--dns_servers"),
            String::from("222.222.222.222"),
            String::from("--clandestine_port"),
            String::from("1234"),
        ];
        let actor_system_factory = ActorSystemFactoryMock::new();
        let mut subject = BootstrapperBuilder::new()
            .actor_system_factory(Box::new(actor_system_factory))
            .add_listener_handler(Box::new(one_listener_handler))
            .add_listener_handler(Box::new(another_listener_handler))
            .add_listener_handler(Box::new(yet_another_listener_handler))
            .build();
        let mut log_initializer: Box<LoggerInitializerWrapper> =
            Box::new(LoggerInitializerWrapperMock::new());
        subject.initialize_as_privileged(&cli_params, &mut log_initializer);

        subject.initialize_as_unprivileged(&mut holder.streams());

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

        let mut log_initializer: Box<LoggerInitializerWrapper> =
            Box::new(LoggerInitializerWrapperMock::new());
        subject.initialize_as_privileged(&make_default_cli_params(), &mut log_initializer);
        subject.initialize_as_unprivileged(&mut holder.streams());

        thread::spawn(|| {
            tokio::run(subject);
        });

        let number_of_expected_messages = 3;
        awaiter.await_message_count(number_of_expected_messages);
        let recording = recording_arc.lock().unwrap();
        assert_eq!(recording.len(), number_of_expected_messages);
        let actual_ports: Vec<String> = (0..number_of_expected_messages)
            .into_iter()
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
    fn no_parameters_produces_configuration_for_crash_point() {
        let args = make_default_cli_params();
        let mut subject = BootstrapperConfig::new();
        Bootstrapper::parse_args(&args, &mut subject);

        assert_eq!(subject.crash_point, CrashPoint::None);
    }

    #[test]
    fn with_parameters_produces_configuration_for_crash_point() {
        let mut args = make_default_cli_params();
        let crash_args = vec![String::from("--crash_point"), String::from("panic")];
        let mut subject = BootstrapperConfig::new();

        args.extend(crash_args);

        Bootstrapper::parse_args(&args, &mut subject);

        assert_eq!(subject.crash_point, CrashPoint::Panic);
    }

    #[test]
    fn establish_clandestine_port_handles_specified_port() {
        let listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .build();
        let mut config = BootstrapperConfig::new();
        let home_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "establish_clandestine_port_handles_specified_port",
        );
        config.neighborhood_config.local_ip_addr = IpAddr::from_str("1.2.3.4").unwrap(); // not sentinel
        config.neighborhood_config.neighbor_configs = vec![NodeDescriptor {
            public_key: PublicKey::new(&[1, 2, 3, 4]),
            node_addr: NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![1234]),
        }];
        config.data_directory = home_dir.clone();
        config.clandestine_port_opt = Some(1234);
        subject.config = Some(config);

        subject.establish_clandestine_port();

        let conn = DbInitializerReal::new().initialize(&home_dir).unwrap();
        let config_dao = ConfigDaoReal::new(conn);
        let persistent_config = PersistentConfigurationReal::new(Box::new(config_dao));
        assert_eq!(1234u16, persistent_config.clandestine_port());
        assert_eq!(
            vec![1234u16],
            subject
                .config
                .as_ref()
                .unwrap()
                .neighborhood_config
                .clandestine_port_list
        );
        assert_eq!(1, subject.listener_handlers.len());

        let config = subject.config.unwrap();
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
        let listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .build();
        let mut config = BootstrapperConfig::new();
        let home_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "establish_clandestine_port_handles_unspecified_port",
        );
        config.neighborhood_config.local_ip_addr = IpAddr::from_str("1.2.3.4").unwrap(); // not sentinel
        config.neighborhood_config.neighbor_configs = vec![NodeDescriptor {
            public_key: PublicKey::new(&[1, 2, 3, 4]),
            node_addr: NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec![1234]),
        }];
        config.data_directory = home_dir.clone();
        config.clandestine_port_opt = None;
        subject.config = Some(config);

        subject.establish_clandestine_port();

        let conn = DbInitializerReal::new().initialize(&home_dir).unwrap();
        let config_dao = ConfigDaoReal::new(conn);
        let persistent_config = PersistentConfigurationReal::new(Box::new(config_dao));
        let clandestine_port = persistent_config.clandestine_port();
        assert_eq!(
            vec![clandestine_port],
            subject
                .config
                .as_ref()
                .unwrap()
                .neighborhood_config
                .clandestine_port_list
        );
    }

    #[test]
    fn establish_clandestine_port_handles_zero_hop() {
        let listener_handler = ListenerHandlerNull::new(vec![]);
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(listener_handler))
            .build();
        let mut config = BootstrapperConfig::new();
        let home_dir = ensure_node_home_directory_exists(
            "bootstrapper",
            "establish_clandestine_port_handles_zero_hop",
        );
        config.data_directory = home_dir.clone();
        config.clandestine_port_opt = None;
        config.neighborhood_config.neighbor_configs = vec![]; // empty
        config.neighborhood_config.local_ip_addr = sentinel_ip_addr(); // sentinel
        config.neighborhood_config.clandestine_port_list = vec![];
        subject.config = Some(config);

        subject.establish_clandestine_port();

        assert!(subject
            .config
            .as_ref()
            .unwrap()
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
        configuration: Option<Configuration>,
        actor_system_factory: Box<dyn ActorSystemFactory>,
        listener_handler_factory: ListenerHandlerFactoryMock,
    }

    impl BootstrapperBuilder {
        fn new() -> BootstrapperBuilder {
            BootstrapperBuilder {
                configuration: None,
                actor_system_factory: Box::new(ActorSystemFactoryMock::new()),
                // Don't modify this line unless you've already looked at DispatcherBuilder::add_listener_handler().
                listener_handler_factory: ListenerHandlerFactoryMock::new(),
            }
        }

        #[allow(dead_code)]
        fn configuration(mut self, configuration: Configuration) -> BootstrapperBuilder {
            self.configuration = Some(configuration);
            self
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

        fn build(self) -> Bootstrapper {
            Bootstrapper {
                actor_system_factory: self.actor_system_factory,
                listener_handler_factory: Box::new(self.listener_handler_factory),
                listener_handlers: FuturesUnordered::<
                    Box<dyn ListenerHandler<Item = (), Error = ()>>,
                >::new(),
                config: None,
            }
        }
    }
}
