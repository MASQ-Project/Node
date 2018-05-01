// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use sub_lib::socket_server::SocketServer;
use sub_lib::main_tools::StdStreams;
use actor_system_factory::ActorSystemFactory;
use actor_system_factory::ActorSystemFactoryReal;
use configuration::Configuration;
use listener_handler::ListenerHandler;
use listener_handler::ListenerHandlerFactory;
use listener_handler::ListenerHandlerFactoryReal;
use stream_handler_pool::StreamHandlerPoolSubs;

struct BootstrapperConfig {
    dns_servers: Vec<SocketAddr>
}

// TODO: Consider splitting this into a piece that's meant for being root and a piece that's not.
pub struct Bootstrapper {
    listener_handler_factory: Box<ListenerHandlerFactory>,
    listener_handlers: Vec<Box<ListenerHandler>>,
    actor_system_factory: Box<ActorSystemFactory>,
    #[allow (dead_code)]
    stream_handler_pool_subs: Option<StreamHandlerPoolSubs>,
    config: Option<BootstrapperConfig>,
}

impl SocketServer for Bootstrapper {
    fn name(&self) -> String {
        String::from ("Dispatcher")
    }

    fn initialize_as_root(&mut self, args: &Vec<String>, _streams: &mut StdStreams) {
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
    }

    fn serve_without_root(&mut self) {
        let stream_handler_pool_subs =
            self.actor_system_factory.make_and_start_actors(
                self.config.as_ref().expect("Missing BootstrapperConfig - call initialize_as_root first").dns_servers.clone(),
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
            stream_handler_pool_subs: None,
            config: None,
        }
    }

    fn start_listener_thread (&self, mut listener_handler: Box<ListenerHandler>) {
        thread::spawn (move || {
            listener_handler.handle_traffic();
        });
    }

    fn parse_args (args: &Vec<String>) -> BootstrapperConfig {
        let dns_server_addrs = {
            let mut shifted = args.iter();
            if shifted.next().is_none() {
                vec! ()
            }
            else {
                let mut zip = args.iter().zip(shifted);
                let dns_server_string_opt = match zip.find(|p| { *p.0 == String::from("--dns_servers") }) {
                    Some(pair) => Some(pair.1),
                    None => None
                };
                let dns_server_strings: Vec<String> = match dns_server_string_opt {
                    Some(dns_server_string) => dns_server_string.split(",").map(|s| { String::from(s) }).collect(),
                    None => vec!()
                };
                dns_server_strings.iter().map(|string| {
                    match IpAddr::from_str(string) {
                        Ok(addr) => SocketAddr::new(addr, 53),
                        Err(_) => panic!("Cannot use '{}' as a DNS server IP address", string)
                    }
                }).collect()
            }
        };
        BootstrapperConfig {
            dns_servers: dns_server_addrs
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::io;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::net::SocketAddr;
    use std::marker::Sync;
    use std::ops::DerefMut;
    use std::str::FromStr;
    use std::sync::mpsc;
    use actix::Subscriber;
    use actix::System;
    use test_utils::test_utils::FakeStreamHolder;
    use test_utils::test_utils::Recorder;
    use test_utils::test_utils::Recording;
    use test_utils::test_utils::RecordAwaiter;
    use test_utils::test_utils::TestLog;
    use discriminator::DiscriminatorFactory;
    use stream_handler_pool::AddStreamMsg;
    use node_test_utils::TcpStreamWrapperMock;
    use node_test_utils::TestLogOwner;
    use node_test_utils::extract_log;
    use node_test_utils::make_stream_handler_pool_subs_from;

    struct ListenerHandlerFactoryMock {
        log: TestLog,
        mocks: RefCell<Vec<ListenerHandlerNull>>
    }

    unsafe impl Sync for ListenerHandlerFactoryMock {}

    impl ListenerHandlerFactory for ListenerHandlerFactoryMock {
        fn make(&self) -> Box<ListenerHandler> {
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
        add_stream_sub: Option<Box<Subscriber<AddStreamMsg> + Send>>,
        add_stream_msgs: Arc<Mutex<Vec<AddStreamMsg>>>
    }

    impl ListenerHandler for ListenerHandlerNull {
        fn bind_port_and_discriminator_factories (&mut self, port: u16, discriminator_factories: Vec<Box<DiscriminatorFactory>>) -> io::Result<()> {
            self.log.lock ().unwrap ().log (format! ("bind_port_and_discriminator_factories ({}, ...)", port));
            self.discriminator_factories_parameter = Some (discriminator_factories);
            self.bind_port_and_discriminator_factories_result.take ().unwrap ()
        }

        fn bind_subs (&mut self, add_stream_sub: Box<Subscriber<AddStreamMsg> + Send>) {
            self.log.lock ().unwrap ().log (format! ("bind_subscribers (add_stream_sub)"));
            self.add_stream_sub = Some (add_stream_sub);
        }

        fn handle_traffic (&mut self) {
            self.log.lock ().unwrap ().log (format! ("handle_traffic (...)"));
            let mut add_stream_msgs = self.add_stream_msgs.lock ().unwrap ();
            let add_stream_sub = self.add_stream_sub.as_ref ().unwrap ();
            while add_stream_msgs.len () > 0 {
                let add_stream_msg = add_stream_msgs.remove (0);
                add_stream_sub.send (add_stream_msg).ok ();
            }
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

    #[test]
    fn knows_its_name () {
        let subject = DispatcherBuilder::new ().build ();

        let result = subject.name ();

        assert_eq! (result, String::from ("Dispatcher"));
    }

    #[test]
    fn initialize_as_root_with_no_args_binds_port_80 () {
        let (first_handler, first_handler_log) = extract_log (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let (second_handler, second_handler_log) = extract_log (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let (third_handler, third_handler_log) = extract_log (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())));
        let mut subject = DispatcherBuilder::new ()
            .add_listener_handler (first_handler)
            .add_listener_handler (second_handler)
            .add_listener_handler (third_handler)
            .build ();

        subject.initialize_as_root(&vec! (), &mut FakeStreamHolder::new ().streams ());

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
        let mut subject = DispatcherBuilder::new ()
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
    #[should_panic (expected = "Cannot use 'booga' as a DNS server IP address")]
    fn initialize_as_root_complains_about_dns_servers_syntax_errors () {
        let mut subject = DispatcherBuilder::new ()
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .build ();

        subject.initialize_as_root(&vec! (String::from ("--dns_servers"), String::from ("booga,booga")),
                                   &mut FakeStreamHolder::new ().streams ());
    }

    #[test]
    #[should_panic (expected = "Could not listen on port")]
    fn initialize_as_root_panics_if_tcp_listener_doesnt_bind () {
        let mut subject = DispatcherBuilder::new ()
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Err (Error::from (ErrorKind::AddrInUse))))
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .build ();

        subject.initialize_as_root(&vec! (String::from ("--dns_servers"), String::from ("1.1.1.1")), &mut FakeStreamHolder::new ().streams ());
    }

    #[test]
    fn serve_without_root_moves_streams_from_listener_handlers_to_stream_handler_pool () {
        let first_message = AddStreamMsg {
            stream: Box::new (TcpStreamWrapperMock::new ().name ("first")),
            origin_port: Some (80),
            discriminator_factories: vec! ()
        };
        let second_message = AddStreamMsg {
            stream: Box::new (TcpStreamWrapperMock::new ().name ("second")),
            origin_port: None,
            discriminator_factories: vec! ()
        };
        let third_message = AddStreamMsg {
            stream: Box::new (TcpStreamWrapperMock::new ().name ("third")),
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
        let mut subject = DispatcherBuilder::new ()
            .actor_system_factory (Box::new (actor_system_factory))
            .add_listener_handler (one_listener_handler)
            .add_listener_handler (another_listener_handler)
            .build ();
        subject.initialize_as_root(&vec! (), &mut FakeStreamHolder::new ().streams ());

        subject.serve_without_root();

        let number_of_expected_messages = 3;
        awaiter.await_message_count (number_of_expected_messages);
        let recording = recording_arc.lock ().unwrap ();
        assert_eq! (recording.len (), number_of_expected_messages);
        let actual_names: Vec<String> = (0..number_of_expected_messages).into_iter().map (|i| {
            let record = recording.get_record::<AddStreamMsg> (i);
            let pptr = &record.stream as *const _;
            let stream_name = unsafe {
                let tptr = pptr as *const Box<TcpStreamWrapperMock>;
                let stream = &*tptr;
                stream.name.clone ()
            };
            format! ("{}/{:?}", stream_name, record.origin_port)

        }).collect ();
        assert_eq! (actual_names.contains (&String::from ("first/Some(80)")), true, "{:?} does not contain 'first'", actual_names);
        assert_eq! (actual_names.contains (&String::from ("second/None")), true, "{:?} does not contain 'second'", actual_names);
        assert_eq! (actual_names.contains (&String::from ("third/Some(443)")), true, "{:?} does not contain 'third'", actual_names);
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
        fn make_and_start_actors(&self, dns_servers: Vec<SocketAddr>) -> StreamHandlerPoolSubs {
            let mut parameter_guard = self.dnss.lock ().unwrap ();
            let parameter_ref = parameter_guard.deref_mut ();
            *parameter_ref = Some (dns_servers);

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

    struct DispatcherBuilder {
        configuration: Option<Configuration>,
        actor_system_factory: Box<ActorSystemFactory>,
        stream_handler_pool_cluster: Option<StreamHandlerPoolCluster>,
        listener_handler_factory: ListenerHandlerFactoryMock,
    }

    impl DispatcherBuilder {
        fn new () -> DispatcherBuilder {
            DispatcherBuilder {
                configuration: None,
                actor_system_factory: Box::new (ActorSystemFactoryMock::new()),
                stream_handler_pool_cluster: None,
                // Don't modify this line unless you've already looked at DispatcherBuilder::add_listener_handler().
                listener_handler_factory: ListenerHandlerFactoryMock::new (),
            }
        }

        #[allow (dead_code)]
        fn configuration (mut self, configuration: Configuration) -> DispatcherBuilder {
            self.configuration = Some (configuration);
            self
        }

        fn actor_system_factory (mut self, actor_system_factory: Box<ActorSystemFactory>) -> DispatcherBuilder {
            self.actor_system_factory = actor_system_factory;
            self
        }

        fn add_listener_handler (mut self, listener_handler: ListenerHandlerNull) -> DispatcherBuilder {
            self.listener_handler_factory.add (listener_handler);
            self
        }

        fn build (self) -> Bootstrapper {
            let stream_handler_pool_subs = match &self.stream_handler_pool_cluster {
                &Some (ref shpc) => Some (shpc.subs.clone ()),
                &None => None
            };
            Bootstrapper {
                actor_system_factory: self.actor_system_factory,
                stream_handler_pool_subs,
                listener_handler_factory: Box::new (self.listener_handler_factory),
                listener_handlers: vec! (),
                config: None,
            }
        }
    }
}
