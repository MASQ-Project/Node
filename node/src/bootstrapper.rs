// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::accountant::accountant::DEFAULT_PAYABLE_SCAN_INTERVAL;
use crate::actor_system_factory::ActorFactoryReal;
use crate::actor_system_factory::ActorSystemFactory;
use crate::actor_system_factory::ActorSystemFactoryReal;
use crate::configuration::Configuration;
use crate::crash_test_dummy::CrashTestDummy;
use crate::discriminator::DiscriminatorFactory;
use crate::listener_handler::ListenerHandler;
use crate::listener_handler::ListenerHandlerFactory;
use crate::listener_handler::ListenerHandlerFactoryReal;
use crate::sub_lib::accountant;
use crate::sub_lib::accountant::AccountantConfig;
use crate::sub_lib::blockchain_bridge::BlockchainBridgeConfig;
use crate::sub_lib::crash_point::CrashPoint;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::neighborhood::sentinel_ip_addr;
use crate::sub_lib::neighborhood::NeighborhoodConfig;
use crate::sub_lib::neighborhood::DEFAULT_RATE_PACK;
use crate::sub_lib::node_addr::NodeAddr;
use crate::sub_lib::parameter_finder::ParameterFinder;
use crate::sub_lib::socket_server::SocketServer;
use crate::sub_lib::ui_gateway::UiGatewayConfig;
use crate::sub_lib::ui_gateway::DEFAULT_UI_PORT;
use crate::sub_lib::wallet::Wallet;
use base64;
use dirs::data_dir;
use futures::try_ready;
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

#[derive(Clone)]
pub struct BootstrapperConfig {
    pub dns_servers: Vec<SocketAddr>,
    pub neighborhood_config: NeighborhoodConfig,
    pub accountant_config: AccountantConfig,
    pub crash_point: CrashPoint,
    pub clandestine_discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    pub ui_gateway_config: UiGatewayConfig,
    pub blockchain_bridge_config: BlockchainBridgeConfig,
}

impl BootstrapperConfig {
    pub fn new() -> BootstrapperConfig {
        BootstrapperConfig {
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
                data_directory: PathBuf::new(),
                payable_scan_interval: Duration::from_secs(DEFAULT_PAYABLE_SCAN_INTERVAL),
            },
            crash_point: CrashPoint::None,
            clandestine_discriminator_factories: vec![],
            ui_gateway_config: UiGatewayConfig {
                ui_port: DEFAULT_UI_PORT,
                node_descriptor: String::from(""),
            },
            blockchain_bridge_config: BlockchainBridgeConfig {
                consuming_private_key: None,
            },
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

    fn initialize_as_privileged(&mut self, args: &Vec<String>, streams: &mut StdStreams<'_>) {
        let mut configuration = Configuration::new();
        configuration.establish(args);
        let cryptde_ref = Bootstrapper::initialize_cryptde();
        let mut config = BootstrapperConfig::new();
        Bootstrapper::parse_args(args, &mut config);
        Bootstrapper::parse_environment_variables(&mut config);
        Bootstrapper::add_clandestine_port_info(&configuration, &mut config);
        config.ui_gateway_config.node_descriptor = Bootstrapper::report_local_descriptor(
            cryptde_ref,
            config.neighborhood_config.local_ip_addr,
            config.neighborhood_config.clandestine_port_list.clone(),
            streams,
        );
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

    fn initialize_as_unprivileged(&mut self) {
        let stream_handler_pool_subs = self.actor_system_factory.make_and_start_actors(
            self.config
                .as_ref()
                .expect("Missing BootstrapperConfig - call initialize_as_root first")
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
        let finder = ParameterFinder::new(args.clone());
        let local_ip_addr = Bootstrapper::parse_ip(&finder);
        config.crash_point = Bootstrapper::parse_crash_point(&finder);
        config.dns_servers = Bootstrapper::parse_dns_servers(&finder);
        config.neighborhood_config.neighbor_configs =
            Bootstrapper::parse_neighbor_configs(&finder, "--neighbor");
        config.neighborhood_config.is_bootstrap_node = Bootstrapper::parse_node_type(&finder);
        config.neighborhood_config.local_ip_addr = local_ip_addr;
        config.ui_gateway_config.ui_port = Bootstrapper::parse_ui_port(&finder);
        config.accountant_config.data_directory =
            Bootstrapper::parse_data_dir(&finder, &RealDirsWrapper {});
        config.neighborhood_config.earning_wallet = Bootstrapper::parse_wallet_address(&finder)
            .unwrap_or(accountant::DEFAULT_EARNING_WALLET.clone());
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

    fn parse_crash_point(finder: &ParameterFinder) -> CrashPoint {
        // TODO FIXME implement crash point values as string instead of numbers
        match finder.find_value_for(
            "--crash_point",
            "--crash_point <number where 1 = panic, 2 = error, default = 0 - no crash)>",
        ) {
            None => CrashPoint::None,
            Some(ref crash_point_str) => match crash_point_str.parse::<usize>() {
                Ok(crash_point) => crash_point.into(),
                Err(_) => panic!("--crash_point needs a number, not '{}'", crash_point_str),
            },
        }
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

    fn is_valid_ethereum_address(address: &str) -> bool {
        Regex::new("^0x[0-9a-fA-F]{40}$")
            .expect("Failed to compile regular expression")
            .is_match(address)
    }

    fn parse_wallet_address(finder: &ParameterFinder) -> Option<Wallet> {
        let usage = "--wallet_address <address> where 'address' is an Ethereum wallet address";
        match finder.find_value_for("--wallet_address", usage) {
            Some(address) => {
                if !Bootstrapper::is_valid_ethereum_address(&address) {
                    panic!(
                        "--wallet_address requires a valid Ethereum wallet address, not '{}'",
                        address
                    );
                }
                Some(Wallet::new(address.as_str()))
            }
            None => None,
        }
    }

    fn parse_ip(finder: &ParameterFinder) -> IpAddr {
        let usage = "--ip <public IP address>";
        match finder.find_value_for("--ip", usage) {
            Some(ip_addr_string) => match IpAddr::from_str(ip_addr_string.as_str()) {
                Ok(ip_addr) => ip_addr,
                Err(_) => panic!(
                    "Invalid IP address for --ip <public IP address>: '{}'",
                    ip_addr_string
                ),
            },
            None => sentinel_ip_addr(),
        }
    }

    fn parse_ui_port(finder: &ParameterFinder) -> u16 {
        let usage = "--ui_port <port number>";
        match finder.find_value_for("--ui_port", usage) {
            Some(port_string) => match str::parse::<u16>(port_string.as_str()) {
                Ok(port_number) if port_number < 1024 => panic!(
                    "Invalid port for --ui_port <port number>: '{}'",
                    port_string
                ),
                Ok(port_number) => port_number,
                Err(_) => panic!(
                    "Invalid port for --ui_port <port number>: '{}'",
                    port_string
                ),
            },
            None => DEFAULT_UI_PORT,
        }
    }

    fn parse_data_dir(finder: &ParameterFinder, dirs_wrapper: &DirsWrapper) -> PathBuf {
        let usage = "--data_directory <directory>";
        match finder.find_value_for("--data_directory", usage) {
            Some(data_directory) => PathBuf::from(data_directory),
            None => dirs_wrapper.data_dir().expect("Could not provide a default data directory, please specify one with --data_directory")
        }
    }

    fn parse_dns_servers(finder: &ParameterFinder) -> Vec<SocketAddr> {
        let parameter_tag = "--dns_servers";
        let usage =
            "--dns_servers <servers> where 'servers' is a comma-separated list of IP addresses";

        let dns_server_strings: Vec<String> = match finder.find_value_for(parameter_tag, usage) {
            Some(dns_server_string) => dns_server_string
                .split(",")
                .map(|s| String::from(s))
                .collect(),
            None => panic!(usage),
        };
        dns_server_strings
            .iter()
            .map(|string| match IpAddr::from_str(string) {
                Ok(addr) => SocketAddr::new(addr, 53),
                Err(_) => panic!(
                    "Invalid IP address for --dns_servers <servers>: '{}'",
                    string
                ),
            })
            .collect()
    }

    fn parse_node_type(finder: &ParameterFinder) -> bool {
        let usage = "--node_type standard|bootstrap";
        match finder.find_value_for("--node_type", usage) {
            None => false,
            Some(ref node_type) if node_type == "standard" => false,
            Some(ref node_type) if node_type == "bootstrap" => true,
            Some(ref node_type) => panic!(
                "--node_type must be either standard or bootstrap, not {}",
                node_type
            ),
        }
    }

    fn parse_neighbor_configs(
        finder: &ParameterFinder,
        parameter_tag: &str,
    ) -> Vec<(PublicKey, NodeAddr)> {
        let usage = &format!(
            "{} <public key>:<IP address>:<port>,<port>,...",
            parameter_tag
        )[..];
        finder
            .find_values_for(parameter_tag, usage)
            .into_iter()
            .map(|s| Bootstrapper::parse_neighbor_config(s, parameter_tag))
            .collect()
    }

    fn parse_neighbor_config(input: String, parameter_tag: &str) -> (PublicKey, NodeAddr) {
        let pieces: Vec<&str> = input.splitn(2, ":").collect();
        if pieces.len() != 2 {
            panic!(
                "{} <public key>:<IP address>:<port>,<port>,... (not {} {})",
                parameter_tag, parameter_tag, input
            )
        }
        let public_key = PublicKey::new(
            &base64::decode(pieces[0]).expect(
                format!(
                    "Invalid Base64 for {} <public key>: '{}'",
                    parameter_tag, pieces[0]
                )
                .as_str(),
            )[..],
        );
        if public_key.is_empty() {
            panic!("Blank public key for --neighbor {}", input)
        }
        let node_addr = NodeAddr::from_str(&pieces[1]).expect(
            format!(
                "Invalid NodeAddr for {} <NodeAddr>: '{}'",
                parameter_tag, pieces[1]
            )
            .as_str(),
        );
        (public_key, node_addr)
    }

    // TODO Possibly should be a method on BootstrapperConfig
    fn add_clandestine_port_info(configuration: &Configuration, config: &mut BootstrapperConfig) {
        let clandestine_ports = configuration.clandestine_ports();
        config.clandestine_discriminator_factories = if clandestine_ports.is_empty() {
            vec![]
        } else {
            configuration
                .port_configurations
                .get(&clandestine_ports[0])
                .expect("Malformed configuration")
                .discriminator_factories
                .clone()
        };
        config.neighborhood_config.clandestine_port_list = clandestine_ports;
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
    use crate::configuration::PortConfiguration;
    use crate::discriminator::Discriminator;
    use crate::discriminator::UnmaskedChunk;
    use crate::node_test_utils::extract_log;
    use crate::node_test_utils::make_stream_handler_pool_subs_from;
    use crate::node_test_utils::TestLogOwner;
    use crate::stream_handler_pool::StreamHandlerPoolSubs;
    use crate::stream_messages::AddStreamMsg;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::parameter_finder::ParameterFinder;
    use crate::sub_lib::stream_connector::ConnectionInfo;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLog;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::RecordAwaiter;
    use crate::test_utils::recorder::Recording;
    use crate::test_utils::test_utils::assert_contains;
    use crate::test_utils::test_utils::FakeStreamHolder;
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
    use std::io::Error;
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
            self.log
                .lock()
                .unwrap()
                .log(format!("bind_port_and_configuration ({}, ...)", port));
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
            String::from("--dns_servers"),
            String::from("222.222.222.222"),
            String::from("--port_count"),
            String::from("0"),
        ]
    }

    #[test]
    fn knows_its_name() {
        let subject = BootstrapperBuilder::new().build();

        let result = subject.name();

        assert_eq!(result, String::from("Dispatcher"));
    }

    #[test]
    fn parse_environment_variables_sets_consuming_private_key_to_none_when_not_specified() {
        let mut config = BootstrapperConfig::new();

        ENVIRONMENT
            .lock()
            .unwrap()
            .remove_var("CONSUMING_PRIVATE_KEY");

        Bootstrapper::parse_environment_variables(&mut config);

        assert_eq!(config.blockchain_bridge_config.consuming_private_key, None);
    }

    #[test]
    fn parse_environment_variables_reads_consuming_private_key_when_specified() {
        let mut config = BootstrapperConfig::new();

        ENVIRONMENT.lock().unwrap().set_var(
            "CONSUMING_PRIVATE_KEY",
            "cc46befe8d169b89db447bd725fc2368b12542113555302598430cb5d5c74ea9",
        );

        Bootstrapper::parse_environment_variables(&mut config);

        ENVIRONMENT
            .lock()
            .unwrap()
            .remove_var("CONSUMING_PRIVATE_KEY");

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
    #[should_panic(
        expected = "Missing value for --wallet_address: --wallet_address <address> where 'address' is an Ethereum wallet address"
    )]
    fn parse_wallet_address_requires_an_address() {
        let finder = ParameterFinder::new(vec![String::from("--wallet_address")]);

        Bootstrapper::parse_wallet_address(&finder);
    }

    #[test]
    #[should_panic(expected = "--wallet_address requires a valid Ethereum wallet address")]
    fn parse_wallet_address_requires_an_address_that_is_42_characters_long() {
        let finder = ParameterFinder::new(vec![
            String::from("--wallet_address"),
            String::from("my-favorite-wallet.com"),
        ]);

        Bootstrapper::parse_wallet_address(&finder);
    }

    #[test]
    #[should_panic(expected = "--wallet_address requires a valid Ethereum wallet address")]
    fn parse_wallet_address_must_start_with_0x() {
        let finder = ParameterFinder::new(vec![
            String::from("--wallet_address"),
            String::from("x0my-favorite-wallet.com222222222222222222"),
        ]);

        Bootstrapper::parse_wallet_address(&finder);
    }

    #[test]
    #[should_panic(expected = "--wallet_address requires a valid Ethereum wallet address")]
    fn parse_wallet_address_must_contain_only_hex_characters() {
        let finder = ParameterFinder::new(vec![
            String::from("--wallet_address"),
            String::from("0x9707f21F95B9839A54605100Ca69dCc2e7eaA26q"),
        ]);

        Bootstrapper::parse_wallet_address(&finder);
    }

    #[test]
    fn parse_wallet_address_returns_none_if_no_address_supplied() {
        let finder = ParameterFinder::new(vec![]);

        assert_eq!(Bootstrapper::parse_wallet_address(&finder), None);
    }

    #[test]
    fn parse_wallet_address_handles_happy_path() {
        let finder = ParameterFinder::new(vec![
            String::from("--wallet_address"),
            String::from("0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"),
        ]);

        assert_eq!(
            Bootstrapper::parse_wallet_address(&finder),
            Some(Wallet::new("0xbDfeFf9A1f4A1bdF483d680046344316019C58CF"))
        );
    }

    #[test]
    #[should_panic(
        expected = "--dns_servers <servers> where 'servers' is a comma-separated list of IP addresses"
    )]
    fn parse_dns_servers_requires_dns_servers() {
        let finder = ParameterFinder::new(vec![
            String::from("--not_dns_servers"),
            String::from("1.2.3.4"),
        ]);

        Bootstrapper::parse_dns_servers(&finder);
    }

    #[test]
    #[should_panic(expected = "Invalid IP address for --dns_servers <servers>: '1.2.3.256'")]
    fn parse_dns_servers_catches_invalid_ip_addresses() {
        let finder = ParameterFinder::new(vec![
            String::from("--dns_servers"),
            String::from("1.2.3.256"),
        ]);

        Bootstrapper::parse_dns_servers(&finder);
    }

    #[test]
    fn parse_dns_servers_ignores_second_server_list() {
        let finder = ParameterFinder::new(
            vec![
                "--dns_servers",
                "1.2.3.4,2.3.4.5",
                "--dns_servers",
                "3.4.5.6",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        );

        let socket_addrs = Bootstrapper::parse_dns_servers(&finder);

        assert_eq!(
            socket_addrs,
            vec!(
                SocketAddr::from_str("1.2.3.4:53").unwrap(),
                SocketAddr::from_str("2.3.4.5:53").unwrap()
            )
        )
    }

    #[test]
    #[should_panic(expected = "--neighbor <public key>:<IP address>:<port>,<port>,...")]
    fn parse_neighbor_configs_requires_two_pieces_to_a_configuration() {
        let finder = ParameterFinder::new(
            vec!["--neighbor", "only_one_piece"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        Bootstrapper::parse_neighbor_configs(&finder, "--neighbor");
    }

    #[test]
    #[should_panic(expected = "Invalid Base64 for --neighbor <public key>: 'bad_key'")]
    fn parse_neighbor_configs_complains_about_bad_base_64() {
        let finder = ParameterFinder::new(
            vec!["--neighbor", "bad_key:1.2.3.4:1234,2345"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        Bootstrapper::parse_neighbor_configs(&finder, "--neighbor");
    }

    #[test]
    #[should_panic(expected = "Blank public key for --neighbor :1.2.3.4:1234,2345")]
    fn parse_neighbor_configs_complains_about_blank_public_key() {
        let finder = ParameterFinder::new(
            vec!["--neighbor", ":1.2.3.4:1234,2345"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        Bootstrapper::parse_neighbor_configs(&finder, "--neighbor");
    }

    #[test]
    #[should_panic(expected = "Invalid NodeAddr for --neighbor <NodeAddr>: 'BadNodeAddr'")]
    fn parse_neighbor_configs_complains_about_bad_node_addr() {
        let finder = ParameterFinder::new(
            vec!["--neighbor", "R29vZEtleQ==:BadNodeAddr"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        Bootstrapper::parse_neighbor_configs(&finder, "--neighbor");
    }

    #[test]
    fn parse_neighbor_configs_handles_the_happy_path() {
        let finder = ParameterFinder::new(
            vec![
                "--booga",
                "R29vZEtleQ:1.2.3.4:1234,2345,3456",
                "--irrelevant",
                "parameter",
                "--booga",
                "QW5vdGhlckdvb2RLZXk:2.3.4.5:4567,5678,6789",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        );

        let result = Bootstrapper::parse_neighbor_configs(&finder, "--booga");

        assert_eq!(
            result,
            vec!(
                (
                    PublicKey::new(b"GoodKey"),
                    NodeAddr::new(
                        &IpAddr::from_str("1.2.3.4").unwrap(),
                        &vec!(1234, 2345, 3456),
                    )
                ),
                (
                    PublicKey::new(b"AnotherGoodKey"),
                    NodeAddr::new(
                        &IpAddr::from_str("2.3.4.5").unwrap(),
                        &vec!(4567, 5678, 6789),
                    )
                )
            )
        )
    }

    #[test]
    fn parse_node_type_handles_standard() {
        let finder = ParameterFinder::new(
            vec!["--node_type", "standard"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        let result = Bootstrapper::parse_node_type(&finder);

        assert_eq!(result, false);
    }

    #[test]
    fn parse_node_type_handles_bootstrap() {
        let finder = ParameterFinder::new(
            vec!["--node_type", "bootstrap"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        let result = Bootstrapper::parse_node_type(&finder);

        assert_eq!(result, true);
    }

    #[test]
    fn parse_node_type_defaults_to_standard() {
        let finder = ParameterFinder::new(
            vec!["--irrelevant", "parameter"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        let result = Bootstrapper::parse_node_type(&finder);

        assert_eq!(result, false);
    }

    #[test]
    #[should_panic(expected = "--node_type must be either standard or bootstrap, not booga")]
    fn parse_node_type_complains_about_bad_node_type() {
        let finder = ParameterFinder::new(
            vec!["--node_type", "booga"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        Bootstrapper::parse_node_type(&finder);
    }

    #[test]
    fn parse_ip_defaults() {
        let finder = ParameterFinder::new(
            vec!["--irrelevant", "parameter"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        let result = Bootstrapper::parse_ip(&finder);

        assert_eq!(result, sentinel_ip_addr())
    }

    #[test]
    #[should_panic(expected = "Invalid IP address for --ip <public IP address>: 'booga'")]
    fn parse_complains_about_bad_ip_address() {
        let finder = ParameterFinder::new(
            vec!["--ip", "booga"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        Bootstrapper::parse_ip(&finder);
    }

    #[test]
    #[should_panic(expected = "Invalid port for --ui_port <port number>: 'booga'")]
    fn parse_complains_about_non_numeric_ui_port() {
        let finder = ParameterFinder::new(
            vec!["--ui_port", "booga"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        Bootstrapper::parse_ui_port(&finder);
    }

    #[test]
    #[should_panic(expected = "Invalid port for --ui_port <port number>: '1023'")]
    fn parse_complains_about_ui_port_too_low() {
        let finder = ParameterFinder::new(
            vec!["--ui_port", "1023"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        Bootstrapper::parse_ui_port(&finder);
    }

    #[test]
    #[should_panic(expected = "Invalid port for --ui_port <port number>: '65536'")]
    fn parse_complains_about_ui_port_too_high() {
        let finder = ParameterFinder::new(
            vec!["--ui_port", "65536"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        Bootstrapper::parse_ui_port(&finder);
    }

    #[test]
    fn parse_ui_port_works() {
        let finder = ParameterFinder::new(
            vec!["--ui_port", "5335"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        let result = Bootstrapper::parse_ui_port(&finder);

        assert_eq!(result, 5335)
    }

    #[test]
    fn parse_ui_port_defaults() {
        let finder = ParameterFinder::new(vec![]);

        let result = Bootstrapper::parse_ui_port(&finder);

        assert_eq!(result, DEFAULT_UI_PORT)
    }

    #[test]
    fn parse_data_directory_works() {
        let finder = ParameterFinder::new(
            vec!["--data_directory", "~/.booga"]
                .into_iter()
                .map(String::from)
                .collect(),
        );
        let mock_dirs_wrapper = MockDirsWrapper {};

        let result = Bootstrapper::parse_data_dir(&finder, &mock_dirs_wrapper);

        assert_eq!(result, PathBuf::from("~/.booga"))
    }

    #[test]
    fn parse_data_directory_defaults() {
        let finder = ParameterFinder::new(vec![]);
        let mock_dirs_wrapper = MockDirsWrapper {};

        let result = Bootstrapper::parse_data_dir(&finder, &mock_dirs_wrapper);

        assert_eq!(result, PathBuf::from("mocked/path"));
    }

    #[test]
    #[should_panic(
        expected = "Could not provide a default data directory, please specify one with --data_directory"
    )]
    fn parse_data_directory_panics_when_none() {
        let finder = ParameterFinder::new(vec![]);
        let bad_mock_dirs_wrapper = BadMockDirsWrapper {};

        let _ = Bootstrapper::parse_data_dir(&finder, &bad_mock_dirs_wrapper);
    }

    #[test]
    fn parse_args_creates_configurations() {
        let args: Vec<String> = vec![
            "--irrelevant",
            "irrelevant",
            "--dns_servers",
            "12.34.56.78,23.45.67.89",
            "--irrelevant",
            "irrelevant",
            "--neighbor",
            "QmlsbA:1.2.3.4:1234,2345",
            "--ip",
            "34.56.78.90",
            "--port_count",
            "2",
            "--neighbor",
            "VGVk:2.3.4.5:3456,4567",
            "--node_type",
            "bootstrap",
            "--ui_port",
            "5335",
            "--irrelevant",
            "irrelevant",
            "--wallet_address",
            "0xbDfeFf9A1f4A1bdF483d680046344316019C58CF",
            "--data_directory",
            "~/.booga",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let mut configuration = Configuration::new();

        configuration.establish(&args);
        let mut config = BootstrapperConfig::new();
        Bootstrapper::parse_args(&args, &mut config);

        assert_eq!(
            config.dns_servers,
            vec!(
                SocketAddr::from_str("12.34.56.78:53").unwrap(),
                SocketAddr::from_str("23.45.67.89:53").unwrap()
            )
        );
        assert_eq!(
            config.neighborhood_config.neighbor_configs,
            vec!(
                (
                    PublicKey::new(b"Bill"),
                    NodeAddr::new(&IpAddr::from_str("1.2.3.4").unwrap(), &vec!(1234, 2345))
                ),
                (
                    PublicKey::new(b"Ted"),
                    NodeAddr::new(&IpAddr::from_str("2.3.4.5").unwrap(), &vec!(3456, 4567))
                ),
            )
        );
        assert_eq!(config.neighborhood_config.is_bootstrap_node, true);
        assert_eq!(
            config.neighborhood_config.local_ip_addr,
            IpAddr::V4(Ipv4Addr::new(34, 56, 78, 90))
        );
        assert_eq!(config.ui_gateway_config.ui_port, 5335);
        assert_eq!(
            config.neighborhood_config.earning_wallet,
            Wallet::new("0xbDfeFf9A1f4A1bdF483d680046344316019C58CF")
        );
        assert_eq!(
            config.accountant_config.data_directory,
            PathBuf::from("~/.booga")
        );
    }

    #[test]
    fn parse_args_works_with_node_type_standard() {
        let args: Vec<String> = vec!["--dns_servers", "12.34.56.78", "--node_type", "standard"]
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
    fn initialize_as_root_with_no_args_binds_port_80_and_443() {
        let _ = INITIALIZATION.lock().unwrap();
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
            all_calls.contains(&String::from("bind_port_and_configuration (80, ...)")),
            "{:?}",
            all_calls
        );
        assert!(
            all_calls.contains(&String::from("bind_port_and_configuration (443, ...)")),
            "{:?}",
            all_calls
        );
        assert_eq!(all_calls.len(), 2, "{:?}", all_calls);
    }

    #[test]
    fn initialize_as_root_reads_environment_variables() {
        let _ = INITIALIZATION.lock().unwrap();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .build();

        ENVIRONMENT.lock().unwrap().set_var(
            "CONSUMING_PRIVATE_KEY",
            "9bc385849a4f9019a0acf7699da91422fdd0a3eb55ff4407e450f2c65e69a9f9",
        );

        subject.initialize_as_privileged(
            &make_default_cli_params(),
            &mut FakeStreamHolder::new().streams(),
        );

        let config = subject.config.unwrap();
        assert_eq!(
            config.blockchain_bridge_config.consuming_private_key,
            Some("9bc385849a4f9019a0acf7699da91422fdd0a3eb55ff4407e450f2c65e69a9f9".to_string())
        );

        assert!(
            ENVIRONMENT
                .lock()
                .unwrap()
                .var("CONSUMING_PRIVATE_KEY")
                .is_err(),
            "CONSUMING_PRIVATE_KEY not cleared"
        );
    }

    #[test]
    fn initialize_as_root_with_no_args_produces_empty_clandestine_discriminator_factories_vector() {
        let _ = INITIALIZATION.lock().unwrap();
        let first_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let second_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(first_handler)
            .add_listener_handler(second_handler)
            .build();

        subject.initialize_as_privileged(
            &make_default_cli_params(),
            &mut FakeStreamHolder::new().streams(),
        );

        let config = subject.config.unwrap();
        assert_eq!(
            config.neighborhood_config.clandestine_port_list.is_empty(),
            true
        );
        assert_eq!(config.clandestine_discriminator_factories.is_empty(), true);
    }

    #[test]
    fn initialize_as_privileged_passes_node_descriptor_to_ui_config() {
        let _ = INITIALIZATION.lock().unwrap();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .build();

        subject.initialize_as_privileged(
            &make_default_cli_params(),
            &mut FakeStreamHolder::new().streams(),
        );

        let config = subject.config.unwrap();
        assert!(config.ui_gateway_config.node_descriptor.len() > 0);
    }

    #[test]
    fn initialize_as_root_with_one_clandestine_port_produces_expected_clandestine_discriminator_factories_vector(
    ) {
        let _ = INITIALIZATION.lock().unwrap();
        let first_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let second_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let third_handler = Box::new(ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())));
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(first_handler)
            .add_listener_handler(second_handler)
            .add_listener_handler(third_handler)
            .build();

        subject.initialize_as_privileged(
            &vec![
                String::from("--dns_servers"),
                String::from("222.222.222.222"),
                String::from("--port_count"),
                String::from("1"),
            ],
            &mut FakeStreamHolder::new().streams(),
        );

        let config = subject.config.unwrap();
        assert_eq!(config.neighborhood_config.clandestine_port_list.len(), 1);
        let mut clandestine_discriminators = config
            .clandestine_discriminator_factories
            .into_iter()
            .map(|factory| factory.make())
            .collect::<Vec<Discriminator>>();
        let mut discriminator = clandestine_discriminators.remove(0);
        discriminator.add_data(&b"{\"component\": \"NBHD\", \"bodyText\": \"Booga\"}"[..]);
        assert_eq!(
            discriminator.take_chunk(),
            Some(UnmaskedChunk {
                chunk: b"Booga".to_vec(),
                last_chunk: true,
                sequenced: false,
            })
        ); // TODO: Where is this 'true' coming from?  Is it a problem?
        assert_eq!(clandestine_discriminators.len(), 0);
    }

    #[test]
    fn initialize_as_root_stores_dns_servers_and_passes_them_to_actor_system_factory_for_proxy_client_in_initialize_as_unprivileged(
    ) {
        let _ = INITIALIZATION.lock().unwrap();
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

        subject.initialize_as_privileged(
            &vec![
                String::from("--dns_servers"),
                String::from("1.2.3.4,2.3.4.5"),
                String::from("--port_count"),
                String::from("0"),
            ],
            &mut FakeStreamHolder::new().streams(),
        );

        subject.initialize_as_unprivileged();

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
    #[should_panic(expected = "Invalid IP address for --dns_servers <servers>: 'booga'")]
    fn initialize_as_root_complains_about_dns_servers_syntax_errors() {
        let _ = INITIALIZATION.lock().unwrap();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .build();

        subject.initialize_as_privileged(
            &vec![
                String::from("--dns_servers"),
                String::from("booga,booga"),
                String::from("--port_count"),
                String::from("0"),
            ],
            &mut FakeStreamHolder::new().streams(),
        );
    }

    #[test]
    #[should_panic(expected = "Could not listen on port")]
    fn initialize_as_root_panics_if_tcp_listener_doesnt_bind() {
        let _ = INITIALIZATION.lock().unwrap();
        let mut subject = BootstrapperBuilder::new()
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![])
                    .bind_port_result(Err(Error::from(ErrorKind::AddrInUse))),
            ))
            .add_listener_handler(Box::new(
                ListenerHandlerNull::new(vec![]).bind_port_result(Ok(())),
            ))
            .build();

        subject.initialize_as_privileged(
            &vec![
                String::from("--dns_servers"),
                String::from("1.1.1.1"),
                String::from("--port_count"),
                String::from("0"),
            ],
            &mut FakeStreamHolder::new().streams(),
        );
    }

    #[test]
    fn initialize_cryptde_and_report_local_descriptor() {
        let _ = INITIALIZATION.lock().unwrap();
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
    fn initialize_as_unprivileged_moves_streams_from_listener_handlers_to_stream_handler_pool() {
        let _ = INITIALIZATION.lock().unwrap();
        init_test_logging();
        let one_listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let another_listener_handler = ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let yet_another_listener_handler =
            ListenerHandlerNull::new(vec![]).bind_port_result(Ok(()));
        let cli_params = vec![
            String::from("--dns_servers"),
            String::from("222.222.222.222"),
            String::from("--port_count"),
            String::from("1"),
        ];
        let actor_system_factory = ActorSystemFactoryMock::new();
        let mut subject = BootstrapperBuilder::new()
            .actor_system_factory(Box::new(actor_system_factory))
            .add_listener_handler(Box::new(one_listener_handler))
            .add_listener_handler(Box::new(another_listener_handler))
            .add_listener_handler(Box::new(yet_another_listener_handler))
            .build();
        subject.initialize_as_privileged(&cli_params, &mut FakeStreamHolder::new().streams());

        subject.initialize_as_unprivileged();

        // Checking log message cause I don't know how to get at add_stream_sub
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec![
            "bind_subscribers (add_stream_sub)",
            "bind_subscribers (add_stream_sub)",
        ]);
    }

    #[test]
    fn bootstrapper_as_future_polls_listener_handler_futures() {
        let _ = INITIALIZATION.lock().unwrap();
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

        subject.initialize_as_privileged(
            &make_default_cli_params(),
            &mut FakeStreamHolder::new().streams(),
        );
        subject.initialize_as_unprivileged();

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
    #[should_panic(expected = "--crash_point needs a number, not 'booga'")]
    fn parse_crash_point_rejects_invalid_integers() {
        let args = vec![
            String::from("command"),
            String::from("--crash_point"),
            String::from("booga"),
        ];
        let finder = ParameterFinder::new(args);

        Bootstrapper::parse_crash_point(&finder);
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
        let crash_args = vec![String::from("--crash_point"), String::from("1")];
        let mut subject = BootstrapperConfig::new();

        args.extend(crash_args);

        Bootstrapper::parse_args(&args, &mut subject);

        assert_eq!(subject.crash_point, CrashPoint::Panic);
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
