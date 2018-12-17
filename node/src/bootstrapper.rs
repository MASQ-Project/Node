// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::vec::Vec;
use base64;
use tokio::prelude::Async;
use tokio::prelude::Future;
use tokio::prelude::Stream;
use tokio::prelude::stream::futures_unordered::FuturesUnordered;
use actor_system_factory::ActorFactoryReal;
use actor_system_factory::ActorSystemFactory;
use actor_system_factory::ActorSystemFactoryReal;
use configuration::Configuration;
use crash_test_dummy::CrashTestDummy;
use listener_handler::ListenerHandler;
use listener_handler::ListenerHandlerFactory;
use listener_handler::ListenerHandlerFactoryReal;
use sub_lib::crash_point::CrashPoint;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::Key;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::main_tools::StdStreams;
use sub_lib::neighborhood::NeighborhoodConfig;
use sub_lib::neighborhood::sentinel_ip_addr;
use sub_lib::node_addr::NodeAddr;
use sub_lib::parameter_finder::ParameterFinder;
use sub_lib::socket_server::SocketServer;
use std::net::Ipv4Addr;
use discriminator::DiscriminatorFactory;
use sub_lib::logger::Logger;

pub static mut CRYPT_DE_OPT: Option<CryptDENull> = None;

#[derive (Clone)]
pub struct BootstrapperConfig {
    pub dns_servers: Vec<SocketAddr>,
    pub neighborhood_config: NeighborhoodConfig,
    pub crash_point: CrashPoint,
    pub clandestine_discriminator_factories: Vec<Box<DiscriminatorFactory>>,
}

impl BootstrapperConfig {
    pub fn new () -> BootstrapperConfig {
        BootstrapperConfig {
            dns_servers: vec! (),
            neighborhood_config: NeighborhoodConfig {
                neighbor_configs: vec! (),
                bootstrap_configs: vec! (),
                is_bootstrap_node: false,
                local_ip_addr: IpAddr::V4 (Ipv4Addr::new (0, 0, 0, 0)),
                clandestine_port_list: vec! (),
            },
            crash_point: CrashPoint::None,
            clandestine_discriminator_factories: vec! (),
        }
    }
}

// TODO: Consider splitting this into a piece that's meant for being root and a piece that's not.
pub struct Bootstrapper {
    listener_handler_factory: Box<ListenerHandlerFactory>,
    listener_handlers: FuturesUnordered<Box<ListenerHandler<Item=(), Error=()>>>,
    actor_system_factory: Box<ActorSystemFactory>,
    config: Option<BootstrapperConfig>,
}

impl Future for Bootstrapper {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        if let Some(ref bootstrap_config) =  self.config {
            try_ready!(CrashTestDummy::new(bootstrap_config.crash_point.clone()).poll());
        }

        try_ready!(self.listener_handlers.poll());
        Ok(Async::Ready(()))
    }
}

impl SocketServer for Bootstrapper {
    fn name(&self) -> String {
        String::from ("Dispatcher")
    }

    fn initialize_as_privileged(&mut self, args: &Vec<String>, streams: &mut StdStreams) {
        let mut configuration = Configuration::new ();
        configuration.establish (args);
        let cryptde_ref = Bootstrapper::initialize_cryptde();
        let mut config = BootstrapperConfig::new ();
        Bootstrapper::parse_args (args, &mut config);
        Bootstrapper::add_clandestine_port_info (&configuration, &mut config);
        Bootstrapper::report_local_descriptor(cryptde_ref, config.neighborhood_config.local_ip_addr,
            config.neighborhood_config.clandestine_port_list.clone(), streams);
        self.config = Some(config);
        self.listener_handlers = FuturesUnordered::<Box<ListenerHandler<Item=(), Error=()>>>::new();

        configuration.port_configurations.iter().for_each(|(port, port_configuration)| {
            let mut listener_handler = self.listener_handler_factory.make();
            match listener_handler.bind_port_and_configuration(*port, port_configuration.clone ()) {
                Ok(()) => (),
                Err(e) => panic! ("Could not listen on port {}: {}", port, e.to_string ())
            }
            self.listener_handlers.push(listener_handler);
        });
    }

    fn initialize_as_unprivileged(&mut self) {
        let stream_handler_pool_subs =
            self.actor_system_factory.make_and_start_actors(
                self.config.as_ref().expect("Missing BootstrapperConfig - call initialize_as_root first").clone(),
                Box::new (ActorFactoryReal {}),
            );
        let mut iter_mut = self.listener_handlers.iter_mut();
        loop {
             match iter_mut.next()  {
                 Some(f) => f.bind_subs(stream_handler_pool_subs.add_sub.clone()),
                 None => break
             }
        }
    }
}

impl Bootstrapper {
    pub fn new () -> Bootstrapper {
        Bootstrapper {
            listener_handler_factory: Box::new (ListenerHandlerFactoryReal::new ()),
            listener_handlers: FuturesUnordered::<Box<ListenerHandler<Item=(), Error=()>>>::new(),
            actor_system_factory: Box::new (ActorSystemFactoryReal {}),
            config: None,
        }
    }

    fn parse_args (args: &Vec<String>, config: &mut BootstrapperConfig) {
        let finder = ParameterFinder::new(args.clone ());
        let local_ip_addr = Bootstrapper::parse_ip (&finder);
        config.crash_point = Bootstrapper::parse_crash_point(&finder);
        config.dns_servers = Bootstrapper::parse_dns_servers (&finder);
        config.neighborhood_config.neighbor_configs = Bootstrapper::parse_neighbor_configs(&finder, "--neighbor");
        config.neighborhood_config.bootstrap_configs = Bootstrapper::parse_neighbor_configs(&finder, "--bootstrap_from");
        config.neighborhood_config.is_bootstrap_node = Bootstrapper::parse_node_type(&finder);
        config.neighborhood_config.local_ip_addr = local_ip_addr;
    }

    fn parse_crash_point(finder: &ParameterFinder) -> CrashPoint {
        // TODO FIXME implement crash point values as string instead of numbers
        match finder.find_value_for("--crash_point", "--crash_point <number where 1 = panic, 2 = error, default = 0 - no crash)>") {
            None => CrashPoint::None,
            Some(ref crash_point_str) => match crash_point_str.parse::<usize>() {
                Ok(crash_point) => crash_point.into(),
                Err(_) => panic!("--crash_point needs a number, not '{}'", crash_point_str)
            }
        }
    }

    fn parse_ip (finder: &ParameterFinder) -> IpAddr {
        let usage = "--ip <public IP address>";
        match finder.find_value_for ("--ip", usage) {
            Some (ip_addr_string) => match IpAddr::from_str (ip_addr_string.as_str ()) {
                Ok (ip_addr) => ip_addr,
                Err (_) => panic!("Invalid IP address for --ip <public IP address>: '{}'", ip_addr_string),
            }
            None => sentinel_ip_addr (),
        }
    }

    fn parse_dns_servers (finder: &ParameterFinder) -> Vec<SocketAddr> {
        let parameter_tag = "--dns_servers";
        let usage = "--dns_servers <servers> where 'servers' is a comma-separated list of IP addresses";

        let dns_server_strings: Vec<String> = match finder.find_value_for(parameter_tag, usage) {
            Some(dns_server_string) => dns_server_string.split(",").map(|s| { String::from(s) }).collect(),
            None => panic! (usage)
        };
        dns_server_strings.iter().map(|string| {
            match IpAddr::from_str(string) {
                Ok(addr) => SocketAddr::new(addr, 53),
                Err(_) => panic!("Invalid IP address for --dns_servers <servers>: '{}'", string)
            }
        }).collect()
    }

    fn parse_node_type(finder: &ParameterFinder) -> bool {
        let usage = "--node_type standard|bootstrap";
        match finder.find_value_for("--node_type", usage) {
            None => false,
            Some(ref node_type) if node_type == "standard" => false,
            Some(ref node_type) if node_type == "bootstrap" => true,
            Some(ref node_type) => panic! ("--node_type must be either standard or bootstrap, not {}", node_type),
        }
    }

    fn parse_neighbor_configs (finder: &ParameterFinder, parameter_tag: &str) -> Vec<(Key, NodeAddr)> {
        let usage = &format!("{} <public key>:<IP address>:<port>,<port>,...", parameter_tag)[..];
        finder.find_values_for (parameter_tag, usage).into_iter ()
            .map (|s|Bootstrapper::parse_neighbor_config (s, parameter_tag))
            .collect ()
    }

    fn parse_neighbor_config (input: String, parameter_tag: &str) -> (Key, NodeAddr) {
        let pieces: Vec<&str> = input.splitn (2, ":").collect ();
        if pieces.len () != 2 {panic! ("{} <public key>:<IP address>:<port>,<port>,... (not {} {})", parameter_tag, parameter_tag, input)}
        let public_key = Key::new (&base64::decode (pieces[0])
            .expect (format! ("Invalid Base64 for {} <public key>: '{}'", parameter_tag, pieces[0]).as_str ())[..]);
        if public_key.data.is_empty () {
            panic! ("Blank public key for --neighbor {}", input)
        }
        let node_addr = NodeAddr::from_str (&pieces[1])
            .expect (format! ("Invalid NodeAddr for {} <NodeAddr>: '{}'", parameter_tag, pieces[1]).as_str ());
        (public_key, node_addr)
    }

    // TODO Possibly should be a method on BootstrapperConfig
    fn add_clandestine_port_info (configuration: &Configuration, config: &mut BootstrapperConfig) {
        let clandestine_ports = configuration.clandestine_ports();
        config.clandestine_discriminator_factories = if clandestine_ports.is_empty () {
            vec! ()
        }
        else {
            configuration.port_configurations.get (&clandestine_ports[0]).expect ("Malformed configuration").discriminator_factories.clone ()
        };
        config.neighborhood_config.clandestine_port_list = clandestine_ports;
    }

    fn initialize_cryptde () -> &'static CryptDE {
        let mut exemplar = CryptDENull::new ();
        exemplar.generate_key_pair();
        let cryptde: &'static CryptDENull = unsafe {
            CRYPT_DE_OPT = Some(exemplar);
            CRYPT_DE_OPT.as_ref().expect("Internal error")
        };
        cryptde
    }

    fn report_local_descriptor(cryptde: &CryptDE, ip_addr: IpAddr, ports: Vec<u16>, streams: &mut StdStreams) {
        let port_strings: Vec<String> = ports.iter ().map (|n| format! ("{}", n)).collect ();
        let port_list = port_strings.join (",");
        writeln! (streams.stdout, "SubstratumNode local descriptor: {}:{}:{}",
                  base64::encode_config (&cryptde.public_key ().data, base64::STANDARD_NO_PAD),
                  ip_addr, port_list).expect ("Internal error");
        Logger::new("Bootstrapper").log(format!("SubstratumNode local descriptor: {}:{}:{}",
                                        base64::encode_config (&cryptde.public_key ().data, base64::STANDARD_NO_PAD),
                                        ip_addr, port_list));
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::marker::Sync;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::ops::DerefMut;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::thread;
    use actix::Recipient;
    use actix::Syn;
    use actix::System;
    use regex::Regex;
    use tokio;
    use tokio::prelude::Async;
    use actor_system_factory::ActorFactory;
    use node_test_utils::extract_log;
    use node_test_utils::make_stream_handler_pool_subs_from;
    use node_test_utils::TestLogOwner;
    use sub_lib::cryptde::PlainData;
    use stream_handler_pool::StreamHandlerPoolSubs;
    use stream_messages::AddStreamMsg;
    use test_utils::test_utils::FakeStreamHolder;
    use test_utils::test_utils::assert_contains;
    use test_utils::recorder::RecordAwaiter;
    use test_utils::recorder::Recording;
    use test_utils::logging::TestLog;
    use test_utils::logging::TestLogHandler;
    use test_utils::logging::init_test_logging;
    use test_utils::tokio_wrapper_mocks::ReadHalfWrapperMock;
    use test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use test_utils::recorder::make_recorder;
    use configuration::PortConfiguration;
    use discriminator::Discriminator;
    use discriminator::UnmaskedChunk;
    use sub_lib::stream_connector::ConnectionInfo;

    struct ListenerHandlerFactoryMock {
        log: TestLog,
        mocks: RefCell<Vec<Box<ListenerHandler<Item=(), Error=()>>>>
    }

    unsafe impl Sync for ListenerHandlerFactoryMock {}

    impl ListenerHandlerFactory for ListenerHandlerFactoryMock {
        fn make(&self) -> Box<ListenerHandler<Item=(), Error=()>> {
            self.log.log (format! ("make ()"));
            self.mocks.borrow_mut ().remove (0)
        }
    }

    impl ListenerHandlerFactoryMock {
        fn new () -> ListenerHandlerFactoryMock {
            ListenerHandlerFactoryMock {
                log: TestLog::new (),
                mocks: RefCell::new (vec! ())
            }
        }

        fn add (&mut self, mock: Box<ListenerHandler<Item=(), Error=()>>) {
            self.mocks.borrow_mut ().push (mock)
        }
    }

    struct ListenerHandlerNull {
        log: Arc<Mutex<TestLog>>,
        bind_port_and_discriminator_factories_result: Option<io::Result<()>>,
        port_configuration_parameter: Option<PortConfiguration>,
        add_stream_sub: Option<Recipient<Syn, AddStreamMsg>>,
        add_stream_msgs: Arc<Mutex<Vec<AddStreamMsg>>>,
        _listen_results: Vec<Box<ListenerHandler<Item=(), Error=()>>>,
    }

    impl ListenerHandler for ListenerHandlerNull {
        fn bind_port_and_configuration(&mut self, port: u16, discriminator_factories: PortConfiguration) -> io::Result<()> {
            self.log.lock ().unwrap ().log (format! ("bind_port_and_configuration ({}, ...)", port));
            self.port_configuration_parameter = Some (discriminator_factories);
            self.bind_port_and_discriminator_factories_result.take ().unwrap ()
        }

        fn bind_subs (&mut self, add_stream_sub: Recipient<Syn, AddStreamMsg>) {
            let logger = Logger::new("ListenerHandler");
            logger.log (format! ("bind_subscribers (add_stream_sub)"));

            self.add_stream_sub = Some (add_stream_sub);
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
                add_stream_sub.try_send(add_stream_msg).expect("StreamHandlerPool is dead");
            }
            Ok(Async::NotReady)
        }
    }

    impl TestLogOwner for ListenerHandlerNull {
        fn get_test_log(&self) -> Arc<Mutex<TestLog>> {self.log.clone ()}
    }

    impl ListenerHandlerNull {
        fn new (add_stream_msgs: Vec<AddStreamMsg>) -> ListenerHandlerNull {
            ListenerHandlerNull {
                log: Arc::new (Mutex::new (TestLog::new ())),
                bind_port_and_discriminator_factories_result: None,
                port_configuration_parameter: None,
                add_stream_sub: None,
                add_stream_msgs: Arc::new (Mutex::new (add_stream_msgs)),
                _listen_results: vec! (),
            }
        }

        fn bind_port_result(mut self, result: io::Result<()>) -> ListenerHandlerNull {
            self.bind_port_and_discriminator_factories_result = Some (result);
            self
        }
    }

    fn make_default_cli_params() -> Vec<String> {
        vec! (String::from ("--dns_servers"), String::from ("222.222.222.222"), String::from ("--port_count"), String::from ("0"))
    }

    #[test]
    fn knows_its_name () {
        let subject = BootstrapperBuilder::new ().build ();

        let result = subject.name ();

        assert_eq! (result, String::from ("Dispatcher"));
    }

    #[test]
    #[should_panic (expected = "--dns_servers <servers> where 'servers' is a comma-separated list of IP addresses")]
    fn parse_dns_servers_requires_dns_servers () {
        let finder = ParameterFinder::new (vec! (String::from ("--not_dns_servers"), String::from ("1.2.3.4")));

        Bootstrapper::parse_dns_servers (&finder);
    }

    #[test]
    #[should_panic (expected = "Invalid IP address for --dns_servers <servers>: '1.2.3.256'")]
    fn parse_dns_servers_catches_invalid_ip_addresses () {
        let finder = ParameterFinder::new (vec! (String::from ("--dns_servers"), String::from ("1.2.3.256")));

        Bootstrapper::parse_dns_servers (&finder);
    }

    #[test]
    fn parse_dns_servers_ignores_second_server_list () {
        let finder = ParameterFinder::new (vec! (
            "--dns_servers", "1.2.3.4,2.3.4.5",
            "--dns_servers", "3.4.5.6"
        ).into_iter ().map (String::from).collect ());

        let socket_addrs = Bootstrapper::parse_dns_servers (&finder);

        assert_eq! (socket_addrs, vec! (
            SocketAddr::from_str ("1.2.3.4:53").unwrap (),
            SocketAddr::from_str ("2.3.4.5:53").unwrap ()
        ))
    }

    #[test]
    #[should_panic (expected = "--neighbor <public key>:<IP address>:<port>,<port>,...")]
    fn parse_neighbor_configs_requires_two_pieces_to_a_configuration () {
        let finder = ParameterFinder::new (vec! (
            "--neighbor", "only_one_piece",
        ).into_iter ().map (String::from).collect ());

        Bootstrapper::parse_neighbor_configs (&finder, "--neighbor");
    }

    #[test]
    #[should_panic (expected = "Invalid Base64 for --neighbor <public key>: 'bad_key'")]
    fn parse_neighbor_configs_complains_about_bad_base_64 () {
        let finder = ParameterFinder::new (vec! (
            "--neighbor", "bad_key:1.2.3.4:1234,2345",
        ).into_iter ().map (String::from).collect ());

        Bootstrapper::parse_neighbor_configs (&finder, "--neighbor");
    }

    #[test]
    #[should_panic (expected = "Blank public key for --neighbor :1.2.3.4:1234,2345")]
    fn parse_neighbor_configs_complains_about_blank_public_key () {
        let finder = ParameterFinder::new (vec! (
            "--neighbor", ":1.2.3.4:1234,2345",
        ).into_iter ().map (String::from).collect ());

        Bootstrapper::parse_neighbor_configs (&finder, "--neighbor");
    }

    #[test]
    #[should_panic (expected = "Invalid NodeAddr for --bootstrap_node <NodeAddr>: 'BadNodeAddr'")]
    fn parse_neighbor_configs_complains_about_bad_node_addr () {
        let finder = ParameterFinder::new (vec! (
            "--bootstrap_node", "R29vZEtleQ==:BadNodeAddr",
        ).into_iter ().map (String::from).collect ());

        Bootstrapper::parse_neighbor_configs (&finder, "--bootstrap_node");
    }

    #[test]
    fn parse_neighbor_configs_handles_the_happy_path () {
        let finder = ParameterFinder::new (vec! (
            "--booga", "R29vZEtleQ:1.2.3.4:1234,2345,3456",
            "--irrelevant", "parameter",
            "--booga", "QW5vdGhlckdvb2RLZXk:2.3.4.5:4567,5678,6789",
        ).into_iter ().map (String::from).collect ());

        let result = Bootstrapper::parse_neighbor_configs (&finder, "--booga");

        assert_eq! (result, vec! (
            (Key::new (b"GoodKey"), NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234, 2345, 3456))),
            (Key::new (b"AnotherGoodKey"), NodeAddr::new (&IpAddr::from_str ("2.3.4.5").unwrap (), &vec! (4567, 5678, 6789)))
        ))
    }

    #[test]
    fn parse_node_type_handles_standard() {
        let finder = ParameterFinder::new (vec! (
            "--node_type", "standard"
        ).into_iter ().map (String::from).collect ());

        let result = Bootstrapper::parse_node_type(&finder);

        assert_eq!(result, false);
    }

    #[test]
    fn parse_node_type_handles_bootstrap() {
        let finder = ParameterFinder::new (vec! (
            "--node_type", "bootstrap"
        ).into_iter ().map (String::from).collect ());

        let result = Bootstrapper::parse_node_type(&finder);

        assert_eq!(result, true);
    }

    #[test]
    fn parse_node_type_defaults_to_standard() {
        let finder = ParameterFinder::new (vec! (
            "--irrelevant", "parameter"
        ).into_iter ().map (String::from).collect ());

        let result = Bootstrapper::parse_node_type(&finder);

        assert_eq!(result, false);
    }

    #[test]
    #[should_panic (expected = "--node_type must be either standard or bootstrap, not booga")]
    fn parse_node_type_complains_about_bad_node_type () {
        let finder = ParameterFinder::new (vec! (
            "--node_type", "booga",
        ).into_iter ().map (String::from).collect ());

        Bootstrapper::parse_node_type (&finder);
    }

    #[test]
    fn parse_ip_defaults () {
        let finder = ParameterFinder::new (vec! (
            "--irrelevant", "parameter"
        ).into_iter ().map (String::from).collect ());

        let result = Bootstrapper::parse_ip (&finder);

        assert_eq!(result, sentinel_ip_addr ())
    }

    #[test]
    #[should_panic (expected = "Invalid IP address for --ip <public IP address>: 'booga'")]
    fn parse_complains_about_bad_ip_address () {
        let finder = ParameterFinder::new (vec! (
            "--ip", "booga"
        ).into_iter ().map (String::from).collect ());

        Bootstrapper::parse_ip (&finder);
    }

    #[test]
    fn parse_args_creates_configurations () {
        let args: Vec<String> = vec! (
            "--irrelevant", "irrelevant",
            "--dns_servers", "12.34.56.78,23.45.67.89",
            "--irrelevant", "irrelevant",
            "--neighbor", "QmlsbA:1.2.3.4:1234,2345",
            "--ip", "34.56.78.90",
            "--port_count", "2",
            "--neighbor", "VGVk:2.3.4.5:3456,4567",
            "--node_type", "bootstrap",
            "--bootstrap_from", "R29vZEtleQ:3.4.5.6:5678",
            "--irrelevant", "irrelevant",
        ).into_iter ().map (String::from).collect ();
        let mut configuration = Configuration::new ();

        configuration.establish (&args);
        let mut config = BootstrapperConfig::new ();
        Bootstrapper::parse_args (&args, &mut config);

        assert_eq! (config.dns_servers, vec! (SocketAddr::from_str ("12.34.56.78:53").unwrap (), SocketAddr::from_str ("23.45.67.89:53").unwrap ()));
        assert_eq! (config.neighborhood_config.neighbor_configs, vec! (
            (Key::new (b"Bill"), NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234, 2345))),
            (Key::new (b"Ted"), NodeAddr::new (&IpAddr::from_str ("2.3.4.5").unwrap (), &vec! (3456, 4567))),
        ));
        assert_eq! (config.neighborhood_config.bootstrap_configs, vec! (
            (Key::new (b"GoodKey"), NodeAddr::new (&IpAddr::from_str ("3.4.5.6").unwrap (), &vec! (5678))),
        ));
        assert_eq! (config.neighborhood_config.is_bootstrap_node, true);
        assert_eq! (config.neighborhood_config.local_ip_addr, IpAddr::V4 (Ipv4Addr::new (34, 56, 78, 90)));
    }

    #[test]
    fn parse_args_works_with_node_type_standard () {
        let args: Vec<String> = vec! (
            "--dns_servers", "12.34.56.78",
            "--node_type", "standard",
        ).into_iter ().map (String::from).collect ();
        let mut config = BootstrapperConfig::new ();

        Bootstrapper::parse_args (&args, &mut config);

        assert_eq! (config.neighborhood_config.is_bootstrap_node, false);
    }

    #[test]
    fn initialize_as_root_with_no_args_binds_port_80_and_443 () {
        let (first_handler, first_handler_log) = extract_log (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let (second_handler, second_handler_log) = extract_log (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let (third_handler, third_handler_log) = extract_log (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let mut subject = BootstrapperBuilder::new ()
            .add_listener_handler (Box::new(first_handler))
            .add_listener_handler (Box::new(second_handler))
            .add_listener_handler (Box::new(third_handler))
            .build ();

        subject.initialize_as_privileged(&make_default_cli_params(), &mut FakeStreamHolder::new ().streams ());

        let mut all_calls = vec! ();
        all_calls.extend (first_handler_log.lock ().unwrap ().dump ());
        all_calls.extend (second_handler_log.lock ().unwrap ().dump ());
        all_calls.extend (third_handler_log.lock ().unwrap ().dump ());
        assert!(all_calls.contains (&String::from ("bind_port_and_configuration (80, ...)")), "{:?}", all_calls);
        assert!(all_calls.contains (&String::from ("bind_port_and_configuration (443, ...)")), "{:?}", all_calls);
        assert_eq! (all_calls.len (), 2, "{:?}", all_calls);
    }

    #[test]
    fn initialize_as_root_with_no_args_produces_empty_clandestine_discriminator_factories_vector () {
        let first_handler = Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let second_handler = Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let mut subject = BootstrapperBuilder::new ()
            .add_listener_handler (first_handler)
            .add_listener_handler (second_handler)
            .build ();

        subject.initialize_as_privileged(&make_default_cli_params(), &mut FakeStreamHolder::new ().streams ());

        let config = subject.config.unwrap ();
        assert_eq! (config.neighborhood_config.clandestine_port_list.is_empty (), true);
        assert_eq! (config.clandestine_discriminator_factories.is_empty (), true);
    }

    #[test]
    fn initialize_as_root_with_one_clandestine_port_produces_expected_clandestine_discriminator_factories_vector () {
        let first_handler= Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let second_handler= Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let third_handler= Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let mut subject = BootstrapperBuilder::new ()
            .add_listener_handler (first_handler)
            .add_listener_handler (second_handler)
            .add_listener_handler (third_handler)
            .build ();

        subject.initialize_as_privileged(&vec! (String::from ("--dns_servers"), String::from ("222.222.222.222"), String::from ("--port_count"), String::from ("1")), &mut FakeStreamHolder::new ().streams ());

        let config = subject.config.unwrap ();
        assert_eq! (config.neighborhood_config.clandestine_port_list.len (), 1);
        let mut clandestine_discriminators = config.clandestine_discriminator_factories.into_iter ()
            .map (|factory| factory.make ())
            .collect::<Vec<Discriminator>> ();
        let mut discriminator = clandestine_discriminators.remove (0);
        discriminator.add_data (&b"{\"component\": \"NBHD\", \"bodyText\": \"Booga\"}"[..]);
        assert_eq! (discriminator.take_chunk (), Some (UnmaskedChunk {chunk: b"Booga".to_vec (), last_chunk: true, sequenced: false })); // TODO: Where is this 'true' coming from?  Is it a problem?
        assert_eq! (clandestine_discriminators.len (), 0);
    }

    #[test]
    fn initialize_as_root_stores_dns_servers_and_passes_them_to_actor_system_factory_for_proxy_client_in_initialize_as_unprivileged () {
        let actor_system_factory = ActorSystemFactoryMock::new();
        let dns_servers_arc = actor_system_factory.dnss.clone();
        let mut subject = BootstrapperBuilder::new ()
            .actor_system_factory (Box::new (actor_system_factory))
            .add_listener_handler (Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (()))))
            .add_listener_handler (Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (()))))
            .add_listener_handler (Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (()))))
            .build ();

        subject.initialize_as_privileged(&vec! (String::from ("--dns_servers"), String::from ("1.2.3.4,2.3.4.5"), String::from ("--port_count"), String::from ("0")),
                                   &mut FakeStreamHolder::new ().streams ());

        subject.initialize_as_unprivileged();


        let dns_servers_guard = dns_servers_arc.lock ().unwrap ();
        assert_eq! (dns_servers_guard.as_ref().unwrap(),
                    &vec! (SocketAddr::from_str ("1.2.3.4:53").unwrap (), SocketAddr::from_str ("2.3.4.5:53").unwrap ()))
    }

    #[test]
    #[should_panic (expected = "Invalid IP address for --dns_servers <servers>: 'booga'")]
    fn initialize_as_root_complains_about_dns_servers_syntax_errors () {
        let mut subject = BootstrapperBuilder::new ()
            .add_listener_handler (Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (()))))
            .add_listener_handler (Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (()))))
            .build ();

        subject.initialize_as_privileged(&vec! (String::from ("--dns_servers"), String::from ("booga,booga"), String::from ("--port_count"), String::from ("0")),
                                   &mut FakeStreamHolder::new ().streams ());
    }

    #[test]
    #[should_panic (expected = "Could not listen on port")]
    fn initialize_as_root_panics_if_tcp_listener_doesnt_bind () {
        let mut subject = BootstrapperBuilder::new ()
            .add_listener_handler (Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Err (Error::from (ErrorKind::AddrInUse)))))
            .add_listener_handler (Box::new(ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (()))))
            .build ();

        subject.initialize_as_privileged(&vec! (String::from ("--dns_servers"), String::from ("1.1.1.1"), String::from ("--port_count"), String::from ("0")),
                                          &mut FakeStreamHolder::new ().streams ());
    }

    #[test]
    fn initialize_cryptde_and_report_local_descriptor() {
        let ip_addr = IpAddr::from_str ("2.3.4.5").unwrap ();
        let ports = vec! (3456u16, 4567u16);
        let mut holder = FakeStreamHolder::new ();
        let cryptde_ref = {
            let mut streams = holder.streams ();

            let cryptde_ref = Bootstrapper::initialize_cryptde();
            Bootstrapper::report_local_descriptor(cryptde_ref, ip_addr, ports, &mut streams);

            cryptde_ref
        };
        assert_ne! (cryptde_ref.private_key ().data, b"uninitialized".to_vec ());
        let stdout_dump = holder.stdout.get_string ();
        let expected_descriptor = format! ("{}:2.3.4.5:3456,4567", base64::encode_config (&cryptde_ref.public_key ().data, base64::STANDARD_NO_PAD));
        let regex = Regex::new(r"SubstratumNode local descriptor: (.+?)\n").unwrap();
        let captured_descriptor = regex.captures (stdout_dump.as_str ()).unwrap ().get (1).unwrap ().as_str ();
        assert_eq! (captured_descriptor, expected_descriptor);

        let expected_data = PlainData::new (b"ho'q ;iaerh;frjhvs;lkjerre");
        let crypt_data = cryptde_ref.encode (&cryptde_ref.public_key (), &expected_data).unwrap ();
        let decrypted_data = cryptde_ref.decode (&crypt_data).unwrap ();
        assert_eq! (decrypted_data, expected_data)

    }

    #[test]
    fn initialize_as_unprivileged_moves_streams_from_listener_handlers_to_stream_handler_pool () {
        init_test_logging();
        let one_listener_handler = ListenerHandlerNull::new (vec! (
        )).bind_port_result (Ok (()));
        let another_listener_handler = ListenerHandlerNull::new (vec! (
        )).bind_port_result (Ok (()));
        let yet_another_listener_handler = ListenerHandlerNull::new(vec! ()).bind_port_result(Ok (()));
        let cli_params = vec! (String::from ("--dns_servers"), String::from ("222.222.222.222"), String::from ("--port_count"), String::from ("1"));
        let actor_system_factory = ActorSystemFactoryMock::new();
        let mut subject = BootstrapperBuilder::new()
            .actor_system_factory(Box::new(actor_system_factory))
            .add_listener_handler(Box::new(one_listener_handler))
            .add_listener_handler(Box::new(another_listener_handler))
            .add_listener_handler (Box::new(yet_another_listener_handler))
            .build();
        subject.initialize_as_privileged(&cli_params, &mut FakeStreamHolder::new().streams());

        subject.initialize_as_unprivileged();

        // Checking log message cause I don't know how to get at add_stream_sub
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!("bind_subscribers (add_stream_sub)","bind_subscribers (add_stream_sub)"));
    }

    #[test]
    fn bootstrapper_as_future_polls_listener_handler_futures() {
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
            origin_port: Some (80),
            port_configuration: PortConfiguration::new(vec!(), false),
        };
        let second_message = AddStreamMsg {
            connection_info: connection_info2,
            origin_port: None,
            port_configuration: PortConfiguration::new(vec!(), false),
        };
        let third_message = AddStreamMsg {
            connection_info: connection_info3,
            origin_port: Some (443),
            port_configuration: PortConfiguration::new(vec!(), false),
        };
        let one_listener_handler = ListenerHandlerNull::new (vec! (
            first_message, second_message
        )).bind_port_result (Ok (()));
        let another_listener_handler = ListenerHandlerNull::new (vec! (
            third_message
        )).bind_port_result (Ok(()));
        let mut actor_system_factory = ActorSystemFactoryMock::new();
        let awaiter = actor_system_factory.stream_handler_pool_cluster.awaiter.take().unwrap();
        let recording_arc = actor_system_factory.stream_handler_pool_cluster.recording.take().unwrap();

        let mut subject = BootstrapperBuilder::new()
            .actor_system_factory(Box::new(actor_system_factory))
            .add_listener_handler(Box::new(one_listener_handler))
            .add_listener_handler(Box::new(another_listener_handler))
            .build();

        subject.initialize_as_privileged(&make_default_cli_params(), &mut FakeStreamHolder::new().streams());
        subject.initialize_as_unprivileged();

        thread::spawn(|| {
            tokio::run(subject);
        });

        let number_of_expected_messages = 3;
        awaiter.await_message_count (number_of_expected_messages);
        let recording = recording_arc.lock ().unwrap ();
        assert_eq! (recording.len (), number_of_expected_messages);
        let actual_ports: Vec<String> = (0..number_of_expected_messages).into_iter().map (|i| {
            let record = recording.get_record::<AddStreamMsg> (i);
            format! ("{:?}", record.origin_port)

        }).collect ();
        assert_contains (&actual_ports, &String::from ("Some(80)"));
        assert_contains (&actual_ports, &String::from ("None"));
        assert_contains (&actual_ports, &String::from ("Some(443)"));
    }

    #[test]
    #[should_panic (expected = "--crash_point needs a number, not 'booga'")]
    fn parse_crash_point_rejects_invalid_integers () {
        let args = vec! (String::from ("command"), String::from ("--crash_point"), String::from ("booga"));
        let finder = ParameterFinder::new (args);

        Bootstrapper::parse_crash_point (&finder);
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
        subs: StreamHandlerPoolSubs
    }

    struct ActorSystemFactoryMock {
        stream_handler_pool_cluster: StreamHandlerPoolCluster,
        dnss: Arc<Mutex<Option<Vec<SocketAddr>>>>,
    }

    impl ActorSystemFactory for ActorSystemFactoryMock {
        fn make_and_start_actors(&self, config: BootstrapperConfig, _actor_factory: Box<ActorFactory>) -> StreamHandlerPoolSubs {
            let mut parameter_guard = self.dnss.lock ().unwrap ();
            let parameter_ref = parameter_guard.deref_mut ();
            *parameter_ref = Some (config.dns_servers);

            self.stream_handler_pool_cluster.subs.clone ()
        }
    }

    impl ActorSystemFactoryMock {
        fn new() -> ActorSystemFactoryMock {
            let (tx, rx) = mpsc::channel ();
            thread::spawn (move || {
                let system = System::new ("test");

                let stream_handler_pool_cluster = {
                    let (stream_handler_pool, awaiter, recording) = make_recorder();
                    StreamHandlerPoolCluster {
                        recording: Some (recording),
                        awaiter: Some (awaiter),
                        subs: make_stream_handler_pool_subs_from(Some (stream_handler_pool))
                    }
                };

                tx.send (stream_handler_pool_cluster).unwrap ();
                system.run ();
            });
            let stream_handler_pool_cluster = rx.recv ().unwrap ();
            ActorSystemFactoryMock {
                stream_handler_pool_cluster,
                dnss: Arc::new(Mutex::new(None)),
            }
        }
    }

    struct BootstrapperBuilder {
        configuration: Option<Configuration>,
        actor_system_factory: Box<ActorSystemFactory>,
        listener_handler_factory: ListenerHandlerFactoryMock,
    }

    impl BootstrapperBuilder {
        fn new () -> BootstrapperBuilder {
            BootstrapperBuilder {
                configuration: None,
                actor_system_factory: Box::new (ActorSystemFactoryMock::new()),
                // Don't modify this line unless you've already looked at DispatcherBuilder::add_listener_handler().
                listener_handler_factory: ListenerHandlerFactoryMock::new (),
            }
        }

        #[allow (dead_code)]
        fn configuration (mut self, configuration: Configuration) -> BootstrapperBuilder {
            self.configuration = Some (configuration);
            self
        }

        fn actor_system_factory (mut self, actor_system_factory: Box<ActorSystemFactory>) -> BootstrapperBuilder {
            self.actor_system_factory = actor_system_factory;
            self
        }

        fn add_listener_handler (mut self, listener_handler: Box<ListenerHandler<Item=(), Error=()>>) -> BootstrapperBuilder {
            self.listener_handler_factory.add (listener_handler);
            self
        }

        fn build (self) -> Bootstrapper {
            Bootstrapper {
                actor_system_factory: self.actor_system_factory,
                listener_handler_factory: Box::new (self.listener_handler_factory),
                listener_handlers: FuturesUnordered::<Box<ListenerHandler<Item=(), Error=()>>>::new(),
                config: None,
            }
        }
    }
}
