// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use actor_system_factory::ActorSystemFactory;
use actor_system_factory::ActorSystemFactoryReal;
use base64;
use tokio;
use tokio::prelude::Async;
use configuration::Configuration;
use listener_handler::ListenerHandler;
use listener_handler::ListenerHandlerFactory;
use listener_handler::ListenerHandlerFactoryReal;
use stream_handler_pool::StreamHandlerPoolSubs;
use sub_lib::cryptde::Key;
use sub_lib::main_tools::StdStreams;
use sub_lib::node_addr::NodeAddr;
use sub_lib::parameter_finder::ParameterFinder;
use sub_lib::socket_server::SocketServer;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde_null::CryptDENull;

pub static mut CRYPT_DE_OPT: Option<CryptDENull> = None;

#[derive (Clone)]
pub struct BootstrapperConfig {
    pub dns_servers: Vec<SocketAddr>,
    pub neighbor_configs: Vec<(Key, NodeAddr)>,
    pub bootstrap_configs: Vec<(Key, NodeAddr)>,
    pub is_bootstrap_node: bool,
}

// TODO: Consider splitting this into a piece that's meant for being root and a piece that's not.
pub struct Bootstrapper {
    listener_handler_factory: Box<ListenerHandlerFactory>,
    listener_handlers: Vec<Box<ListenerHandler<Item=(), Error=()>>>,
    actor_system_factory: Box<ActorSystemFactory>,
    config: Option<BootstrapperConfig>,
}

impl SocketServer for Bootstrapper {
    fn name(&self) -> String {
        String::from ("Dispatcher")
    }

    fn initialize_as_root(&mut self, args: &Vec<String>, streams: &mut StdStreams) {
        let mut configuration = Configuration::new ();
        configuration.establish (args);
        self.listener_handlers = configuration.ports ().iter ().map (|port_ref| {
            let mut listener_handler =
                self.listener_handler_factory.make ();
            let discriminator_factories = configuration.take_discriminator_factories_for (*port_ref);
            match listener_handler.bind_port_and_discriminator_factories (*port_ref, discriminator_factories) {
                Ok(()) => (),
                Err(e) => panic! ("Could not listen on port {}: {}", port_ref, e.to_string ())
            }
            listener_handler
        }).collect ();
        self.config = Some(Bootstrapper::parse_args (args));
        Bootstrapper::initialize_and_report_cryptde (streams);
    }

    fn serve_without_root(&mut self) {
        let stream_handler_pool_subs =
            self.actor_system_factory.make_and_start_actors(
                self.config.as_ref().expect("Missing BootstrapperConfig - call initialize_as_root first").clone(),
            );

        while self.listener_handlers.len () > 0 {
            let mut listener_handler = self.listener_handlers.remove (0);
            listener_handler.bind_subs(stream_handler_pool_subs.add_sub.clone ());
            self.start_listener_thread (listener_handler);
        }
    }
}

impl Bootstrapper {
    pub fn new () -> Bootstrapper {
        Bootstrapper {
            listener_handler_factory: Box::new (ListenerHandlerFactoryReal::new ()),
            listener_handlers: vec! (),
            actor_system_factory: Box::new (ActorSystemFactoryReal {}),
            config: None,
        }
    }

    fn start_listener_thread (&self, listener_handler: Box<ListenerHandler<Item=(), Error=()>>) {
        // TODO can we eliminate the thread-per-listener here?
        thread::spawn (move || {
            tokio::run(listener_handler);
        });
    }

    fn parse_args (args: &Vec<String>) -> BootstrapperConfig {
        let finder = ParameterFinder::new(args.clone ());
        BootstrapperConfig {
            dns_servers: Bootstrapper::parse_dns_servers (&finder),
            neighbor_configs: Bootstrapper::parse_neighbor_configs (&finder, "--neighbor"),
            bootstrap_configs: Bootstrapper::parse_neighbor_configs(&finder, "--bootstrap_from"),
            is_bootstrap_node: Bootstrapper::parse_node_type (&finder),
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
        let usage = &format! ("{} <public key>;<IP address>;<port>,<port>,...", parameter_tag)[..];
        finder.find_values_for (parameter_tag, usage).into_iter ()
            .map (|s|Bootstrapper::parse_neighbor_config (s, parameter_tag))
            .collect ()
    }

    fn parse_neighbor_config (string: String, parameter_tag: &str) -> (Key, NodeAddr) {
        let pieces: Vec<&str> = string.split (";").collect ();
        if pieces.len () != 3 {panic! ("{} <public key>;<IP address>;<port>,<port>,...", parameter_tag)}
        let public_key = Key::new (&base64::decode (pieces[0])
            .expect (format! ("Invalid Base64 for {} <public key>: '{}'", parameter_tag, pieces[0]).as_str ())[..]);
        let ip_addr = IpAddr::from_str (&pieces[1])
            .expect (format! ("Invalid IP address for {} <IP address>: '{}'", parameter_tag, pieces[1]).as_str ());
        let ports: Vec<u16> = pieces[2].split (",").map (|s| s.parse::<u16>()
            .expect(format! ("{} port numbers must be 0-65535, not {}", parameter_tag, s).as_str ())).collect ();
        (public_key, NodeAddr::new (&ip_addr, &ports))
    }

    fn initialize_and_report_cryptde (streams: &mut StdStreams) {
        let mut exemplar = CryptDENull::new ();
        exemplar.generate_key_pair();
        let cryptde: &'static CryptDENull = unsafe {
            CRYPT_DE_OPT = Some(exemplar);
            CRYPT_DE_OPT.as_ref().expect("Internal error")
        };
        let public_key_base64 = base64::encode (&cryptde.public_key ().data);
        writeln! (streams.stdout, "Substratum Node public key: {}", public_key_base64).expect ("Internal error");
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
    use std::net::SocketAddr;
    use std::ops::DerefMut;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use actix::Recipient;
    use actix::Syn;
    use actix::System;
    use regex::Regex;
    use tokio::prelude::Future;
    use discriminator::DiscriminatorFactory;
    use node_test_utils::extract_log;
    use node_test_utils::make_stream_handler_pool_subs_from;
    use node_test_utils::TestLogOwner;
    use stream_messages::AddStreamMsg;
    use test_utils::test_utils::FakeStreamHolder;
    use test_utils::test_utils::RecordAwaiter;
    use test_utils::test_utils::Recorder;
    use test_utils::test_utils::Recording;
    use test_utils::test_utils::TestLog;
    use sub_lib::cryptde::PlainData;

    struct ListenerHandlerFactoryMock {
        log: TestLog,
        mocks: RefCell<Vec<ListenerHandlerNull>>
    }

    unsafe impl Sync for ListenerHandlerFactoryMock {}

    impl ListenerHandlerFactory for ListenerHandlerFactoryMock {
        fn make(&self) -> Box<ListenerHandler<Item=(), Error=()>> {
            self.log.log (format! ("make ()"));
            Box::new (self.mocks.borrow_mut ().remove (0))
        }
    }

    impl ListenerHandlerFactoryMock {
        fn new () -> ListenerHandlerFactoryMock {
            ListenerHandlerFactoryMock {
                log: TestLog::new (),
                mocks: RefCell::new (vec! ())
            }
        }

        fn add (&mut self, mock: ListenerHandlerNull) {
            self.mocks.borrow_mut ().push (mock)
        }
    }

    struct ListenerHandlerNull {
        log: Arc<Mutex<TestLog>>,
        bind_port_and_discriminator_factories_result: Option<io::Result<()>>,
        discriminator_factories_parameter: Option<Vec<Box<DiscriminatorFactory>>>,
        add_stream_sub: Option<Recipient<Syn, AddStreamMsg>>,
        add_stream_msgs: Arc<Mutex<Vec<AddStreamMsg>>>
    }

    impl ListenerHandler for ListenerHandlerNull {
        fn bind_port_and_discriminator_factories (&mut self, port: u16, discriminator_factories: Vec<Box<DiscriminatorFactory>>) -> io::Result<()> {
            self.log.lock ().unwrap ().log (format! ("bind_port_and_discriminator_factories ({}, ...)", port));
            self.discriminator_factories_parameter = Some (discriminator_factories);
            self.bind_port_and_discriminator_factories_result.take ().unwrap ()
        }

        fn bind_subs (&mut self, add_stream_sub: Recipient<Syn, AddStreamMsg>) {
            self.log.lock ().unwrap ().log (format! ("bind_subscribers (add_stream_sub)"));
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
                discriminator_factories_parameter: None,
                add_stream_sub: None,
                add_stream_msgs: Arc::new (Mutex::new (add_stream_msgs))
            }
        }

        fn bind_port_result(mut self, result: io::Result<()>) -> ListenerHandlerNull {
            self.bind_port_and_discriminator_factories_result = Some (result);
            self
        }
    }

    fn meaningless_dns_servers() -> Vec<String> {
        vec! (String::from ("--dns_servers"), String::from ("222.222.222.222"))
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
    #[should_panic (expected = "--neighbor <public key>;<IP address>;<port>,<port>,...")]
    fn parse_neighbor_configs_requires_three_pieces_to_a_configuration () {
        let finder = ParameterFinder::new (vec! (
            "--neighbor", "key;1.2.3.4;1234,2345;extra",
        ).into_iter ().map (String::from).collect ());

        Bootstrapper::parse_neighbor_configs (&finder, "--neighbor");
    }

    #[test]
    #[should_panic (expected = "Invalid Base64 for --neighbor <public key>: 'bad_key'")]
    fn parse_neighbor_configs_complains_about_bad_base_64 () {
        let finder = ParameterFinder::new (vec! (
            "--neighbor", "bad_key;1.2.3.4;1234,2345",
        ).into_iter ().map (String::from).collect ());

        Bootstrapper::parse_neighbor_configs (&finder, "--neighbor");
    }

    #[test]
    #[should_panic (expected = "Invalid IP address for --bootstrap_node <IP address>: '1.2.3.256'")]
    fn parse_neighbor_configs_complains_about_bad_ip_address () {
        let finder = ParameterFinder::new (vec! (
            "--bootstrap_node", "GoodKey;1.2.3.256;1234,2345",
        ).into_iter ().map (String::from).collect ());

        Bootstrapper::parse_neighbor_configs (&finder, "--bootstrap_node");
    }

    #[test]
    #[should_panic (expected = "--bootstrap_node port numbers must be 0-65535, not 65536")]
    fn parse_neighbor_configs_complains_about_bad_port_numbers () {
        let finder = ParameterFinder::new (vec! (
            "--bootstrap_node", "GoodKey;1.2.3.4;65536",
        ).into_iter ().map (String::from).collect ());

        Bootstrapper::parse_neighbor_configs (&finder, "--bootstrap_node");
    }

    #[test]
    fn parse_neighbor_configs_handles_the_happy_path () {
        let finder = ParameterFinder::new (vec! (
            "--booga", "R29vZEtleQ;1.2.3.4;1234,2345,3456",
            "--irrelevant", "parameter",
            "--booga", "QW5vdGhlckdvb2RLZXk;2.3.4.5;4567,5678,6789",
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
    fn parse_args_creates_configurations () {
        let args: Vec<String> = vec! (
            "--irrelevant", "irrelevant",
            "--dns_servers", "12.34.56.78,23.45.67.89",
            "--irrelevant", "irrelevant",
            "--neighbor", "QmlsbA;1.2.3.4;1234,2345",
            "--neighbor", "VGVk;2.3.4.5;3456,4567",
            "--node_type", "bootstrap",
            "--bootstrap_from", "R29vZEtleQ;3.4.5.6;5678"
        ).into_iter ().map (String::from).collect ();

        let config = Bootstrapper::parse_args (&args);

        assert_eq! (config.dns_servers, vec! (SocketAddr::from_str ("12.34.56.78:53").unwrap (), SocketAddr::from_str ("23.45.67.89:53").unwrap ()));
        assert_eq! (config.neighbor_configs, vec! (
            (Key::new (b"Bill"), NodeAddr::new (&IpAddr::from_str ("1.2.3.4").unwrap (), &vec! (1234, 2345))),
            (Key::new (b"Ted"), NodeAddr::new (&IpAddr::from_str ("2.3.4.5").unwrap (), &vec! (3456, 4567))),
        ));
        assert_eq! (config.bootstrap_configs, vec! (
            (Key::new (b"GoodKey"), NodeAddr::new (&IpAddr::from_str ("3.4.5.6").unwrap (), &vec! (5678))),
        ));
        assert_eq! (config.is_bootstrap_node, true);
    }

    #[test]
    fn parse_args_works_with_node_type_standard () {
        let args: Vec<String> = vec! (
            "--dns_servers", "12.34.56.78",
            "--node_type", "standard",
        ).into_iter ().map (String::from).collect ();

        let config = Bootstrapper::parse_args (&args);

        assert_eq! (config.is_bootstrap_node, false);
    }

    #[test]
    fn initialize_as_root_with_no_args_binds_port_80 () {
        let (first_handler, first_handler_log) = extract_log (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let (second_handler, second_handler_log) = extract_log (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let (third_handler, third_handler_log) = extract_log (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let mut subject = BootstrapperBuilder::new ()
            .add_listener_handler (first_handler)
            .add_listener_handler (second_handler)
            .add_listener_handler (third_handler)
            .build ();

        subject.initialize_as_root(&meaningless_dns_servers(), &mut FakeStreamHolder::new ().streams ());

        let mut all_calls = vec! ();
        all_calls.extend (first_handler_log.lock ().unwrap ().dump ());
        all_calls.extend (second_handler_log.lock ().unwrap ().dump ());
        all_calls.extend (third_handler_log.lock ().unwrap ().dump ());
        assert_eq! (all_calls.contains (&String::from ("bind_port_and_discriminator_factories (80, ...)")), true, "{:?}", all_calls);
        assert_eq! (all_calls.contains (&String::from ("bind_port_and_discriminator_factories (443, ...)")), true, "{:?}", all_calls);
        assert_eq! (all_calls.len (), 2, "{:?}", all_calls);
    }

    #[test]
    fn initialize_as_root_stores_dns_servers_and_passes_them_to_actor_system_factory_for_proxy_client_in_serve_without_root () {
        let actor_system_factory = ActorSystemFactoryMock::new();
        let dns_servers_arc = actor_system_factory.dnss.clone();
        let mut subject = BootstrapperBuilder::new ()
            .actor_system_factory (Box::new (actor_system_factory))
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .build ();

        subject.initialize_as_root(&vec! (String::from ("--dns_servers"), String::from ("1.2.3.4,2.3.4.5")),
                                   &mut FakeStreamHolder::new ().streams ());

        subject.serve_without_root();


        let dns_servers_guard = dns_servers_arc.lock ().unwrap ();
        assert_eq! (dns_servers_guard.as_ref().unwrap(),
                    &vec! (SocketAddr::from_str ("1.2.3.4:53").unwrap (), SocketAddr::from_str ("2.3.4.5:53").unwrap ()))
    }

    #[test]
    #[should_panic (expected = "Invalid IP address for --dns_servers <servers>: 'booga'")]
    fn initialize_as_root_complains_about_dns_servers_syntax_errors () {
        let mut subject = BootstrapperBuilder::new ()
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .build ();

        subject.initialize_as_root(&vec! (String::from ("--dns_servers"), String::from ("booga,booga")),
                                   &mut FakeStreamHolder::new ().streams ());
    }

    #[test]
    #[should_panic (expected = "Could not listen on port")]
    fn initialize_as_root_panics_if_tcp_listener_doesnt_bind () {
        let mut subject = BootstrapperBuilder::new ()
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Err (Error::from (ErrorKind::AddrInUse))))
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .build ();

        subject.initialize_as_root(&vec! (String::from ("--dns_servers"), String::from ("1.1.1.1")), &mut FakeStreamHolder::new ().streams ());
    }

    #[test]
    fn initialize_and_report_cryptde () {
        let mut holder = FakeStreamHolder::new ();

        {
            let mut streams = holder.streams ();
            Bootstrapper::initialize_and_report_cryptde(&mut streams);
        }

        let cryptde = unsafe {
            CRYPT_DE_OPT.as_ref().expect("Internal error")
        };
        assert_ne! (cryptde.private_key ().data, b"uninitialized".to_vec ());
        let expected_public_key = base64::encode (&cryptde.public_key ().data);
        let stdout_dump = holder.stdout.get_string ();
        let regex = Regex::new(r"Substratum Node public key: (.+?)\n").unwrap();
        let captured_public_key = regex.captures (stdout_dump.as_str ()).unwrap ().get (1).unwrap ().as_str ();
        assert_eq! (captured_public_key, expected_public_key);
        let expected_data = PlainData::new (b"ho'q ;iaerh;frjhvs;lkjerre");
        let crypt_data = cryptde.encode (&cryptde.private_key (), &expected_data).unwrap ();
        let decrypted_data = cryptde.decode (&cryptde.public_key (), &crypt_data).unwrap ();
        assert_eq! (decrypted_data, expected_data)
    }

    #[test]
    fn serve_without_root_moves_streams_from_listener_handlers_to_stream_handler_pool () {
        let first_message = AddStreamMsg {
            stream: None,
            origin_port: Some (80),
            discriminator_factories: vec! ()
        };
        let second_message = AddStreamMsg {
            stream: None,
            origin_port: None,
            discriminator_factories: vec! ()
        };
        let third_message = AddStreamMsg {
            stream: None,
            origin_port: Some (443),
            discriminator_factories: vec! ()
        };
        let one_listener_handler = ListenerHandlerNull::new (vec! (
            first_message, second_message
        )).bind_port_result (Ok (()));
        let another_listener_handler = ListenerHandlerNull::new (vec! (
            third_message
        )).bind_port_result (Ok (()));
        let mut actor_system_factory = ActorSystemFactoryMock::new();
        let awaiter = actor_system_factory.stream_handler_pool_cluster.awaiter.take ().unwrap ();
        let recording_arc = actor_system_factory.stream_handler_pool_cluster.recording.take ().unwrap ();
        let mut subject = BootstrapperBuilder::new ()
            .actor_system_factory (Box::new (actor_system_factory))
            .add_listener_handler (one_listener_handler)
            .add_listener_handler (another_listener_handler)
            .build ();
        subject.initialize_as_root(&meaningless_dns_servers(), &mut FakeStreamHolder::new ().streams ());

        subject.serve_without_root();

        let number_of_expected_messages = 3;
        awaiter.await_message_count (number_of_expected_messages);
        let recording = recording_arc.lock ().unwrap ();
        assert_eq! (recording.len (), number_of_expected_messages);
        let actual_ports: Vec<String> = (0..number_of_expected_messages).into_iter().map (|i| {
            let record = recording.get_record::<AddStreamMsg> (i);
            format! ("{:?}", record.origin_port)

        }).collect ();
        assert_eq! (actual_ports.contains (&String::from ("Some(80)")), true, "{:?} does not contain 'first'", actual_ports);
        assert_eq! (actual_ports.contains (&String::from ("None")), true, "{:?} does not contain 'second'", actual_ports);
        assert_eq! (actual_ports.contains (&String::from ("Some(443)")), true, "{:?} does not contain 'third'", actual_ports);
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
        fn make_and_start_actors(&self, config: BootstrapperConfig) -> StreamHandlerPoolSubs {
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
                    let stream_handler_pool = Recorder::new();
                    let recording = stream_handler_pool.get_recording();
                    let awaiter = stream_handler_pool.get_awaiter();
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

        fn add_listener_handler (mut self, listener_handler: ListenerHandlerNull) -> BootstrapperBuilder {
            self.listener_handler_factory.add (listener_handler);
            self
        }

        fn build (self) -> Bootstrapper {
            Bootstrapper {
                actor_system_factory: self.actor_system_factory,
                listener_handler_factory: Box::new (self.listener_handler_factory),
                listener_handlers: vec! (),
                config: None,
            }
        }
    }
}
