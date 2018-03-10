// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::sync::Mutex;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use actix::Subscriber;
use actix::System;
use actix::SyncAddress;
use sub_lib::dispatcher::DispatcherClient;
use sub_lib::dispatcher::Component;
use sub_lib::dispatcher::Endpoint;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::dispatcher::OutboundClientData;
use sub_lib::dispatcher::PeerClients;
use sub_lib::dispatcher::DispatcherFacadeSubs;
use sub_lib::socket_server::SocketServer;
use sub_lib::limiter::Limiter;
use sub_lib::logger::Logger;
use sub_lib::main_tools::StdStreams;
use sub_lib::hopper::Hopper;
use sub_lib::neighborhood::Neighborhood;
use sub_lib::proxy_client::ProxyClient;
use sub_lib::cryptde::PlainData;
use sub_lib::actor_messages::RequestMessage;
use sub_lib::actor_messages::TemporaryBindMessage;
use sub_lib::stream_handler_pool::TransmitDataMsg;
use sub_lib::stream_handler_pool::StreamHandlerPoolSubs;
use client_factory::ClientFactory;
use client_factory::ClientFactoryReal;
use transmitter::Transmitter;
use transmitter::TransmitterFactory;
use transmitter::TransmitterFactoryReal;
use listener_handler::ListenerHandler;
use listener_handler::ListenerHandlerFactory;
use listener_handler::ListenerHandlerFactoryReal;
use dispatcher_facade::DispatcherFacade;
use configuration::Configuration;
use actor_system_factory::ActorSystemFactory;
use actor_system_factory::ActorSystemFactoryReal;

// TODO: Consider splitting this into a piece that's meant for being root and a piece that's not.
pub struct DispatcherReal {
    listener_handler_factory: Box<ListenerHandlerFactory>,
    listener_handlers: Vec<Box<ListenerHandler>>,

    actor_system_factory: Box<ActorSystemFactory>,
    #[allow (dead_code)]
    stream_handler_pool_subs: Option<StreamHandlerPoolSubs>,
    neighborhood: Option<Arc<Mutex<Neighborhood>>>,
    hopper: Option<Arc<Mutex<Hopper>>>,
    proxy_client: Option<Arc<Mutex<ProxyClient>>>,
    client_factory: Box<ClientFactory>,
    transmitter_factory: Box<TransmitterFactory>,
    incoming_limiter: Limiter,
    logger: Logger,
}

impl SocketServer for DispatcherReal {
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
        let config = DispatcherReal::parse_args (args);
        self.make_clients (config.dns_servers.clone ());
    }

    fn serve_without_root (&mut self) {
        let (ibcd_transmitter, ibcd_receiver) = mpsc::channel ();

        let (dispatcher_facade_subs, stream_handler_pool_subs) =
            self.actor_system_factory.make_and_start_actors(
                ibcd_transmitter,
                self.hopper.as_ref().expect("Hopper has not been created").clone()
            );

        self.start_transmitter_thread (stream_handler_pool_subs.transmit_sub.clone (), dispatcher_facade_subs);

        while self.listener_handlers.len () > 0 {
            let mut listener_handler = self.listener_handlers.remove (0);
            listener_handler.bind_subs(stream_handler_pool_subs.add_sub.clone ());
            self.start_listener_thread (listener_handler);
        }

        self.relay_data_to_clients (ibcd_receiver);
    }
}

impl DispatcherReal {
    pub fn new () -> DispatcherReal {
        DispatcherReal {
            listener_handler_factory: Box::new (ListenerHandlerFactoryReal::new ()),
            listener_handlers: vec! (),

            actor_system_factory: Box::new (ActorSystemFactoryReal {}),
            stream_handler_pool_subs: None,
            neighborhood: None,
            hopper: None,
            proxy_client: None,
            client_factory: Box::new (ClientFactoryReal::new ()),
            transmitter_factory: Box::new (TransmitterFactoryReal::new ()),
            incoming_limiter: Limiter::new (),
            logger: Logger::new ("Dispatcher"),
        }
    }

    fn start_listener_thread (&self, mut listener_handler: Box<ListenerHandler>) {
        thread::spawn (move || {
            listener_handler.handle_traffic();
        });
    }

    fn make_clients (&mut self, dns_servers: Vec<SocketAddr>) {
        self.neighborhood = Some (self.client_factory.make_neighborhood ());
        self.hopper = Some (self.client_factory.make_hopper ());
        self.proxy_client = Some (self.client_factory.make_proxy_client (dns_servers));
    }

    fn start_transmitter_thread (&mut self, transmit_sub: Box<Subscriber<TransmitDataMsg> + Send>, dispatcher_facade_subs: DispatcherFacadeSubs) {
        let (obcd_transmitter,
            obcd_receiver) = mpsc::channel ();
        let neighborhood_arc = self.neighborhood.as_ref ().expect ("Internal error").clone ();
        let mut transmitter_box = self.transmitter_factory.make(obcd_receiver, transmit_sub, neighborhood_arc);

        let peer_clients = PeerClients {
            hopper: self.hopper.as_ref().expect("Must make_clients before start_transmitter_thread").clone (),
            neighborhood: self.neighborhood.as_ref().expect("Must make_clients before start_transmitter_thread").clone (),
            proxy_client: self.proxy_client.as_ref().expect("Must make_clients before start_transmitter_thread").clone (),
        };

        DispatcherReal::bind_client (&self.neighborhood, Component::Neighborhood,
                                     &mut transmitter_box, &obcd_transmitter, &peer_clients);
        DispatcherReal::bind_client (&self.hopper, Component::Hopper,
                                     &mut transmitter_box, &obcd_transmitter, &peer_clients);
        DispatcherReal::bind_client (&self.proxy_client, Component::ProxyClient,
                                     &mut transmitter_box, &obcd_transmitter, &peer_clients);

        // TODO this should go away once everything is actorized
        let ps_transmitter_handle = transmitter_box.make_handle(Component::ProxyServer, &obcd_transmitter);
        dispatcher_facade_subs.transmitter_bind.send(TemporaryBindMessage { transmitter_handle: Box::new(ps_transmitter_handle)});

        thread::spawn (move || {
            transmitter_box.handle_traffic()
        });
    }

    fn relay_data_to_clients (&mut self, data_receiver: Receiver<InboundClientData>) {
        while self.incoming_limiter.should_continue() {
            let ibcd = match data_receiver.recv () {
                Ok (client_data) => client_data,
                Err (_) => break
            };
            let source = {
                let neighborhood_arc = self.neighborhood.as_ref ().expect ("Internal error");
                let neighborhood = neighborhood_arc.lock ().expect ("Internal error");
                match neighborhood.public_key_from_ip_address(&ibcd.socket_addr.ip ()) {
                    Some(public_key) => Endpoint::Key (public_key),
                    None => Endpoint::Socket (ibcd.socket_addr)
                }
            };
            let data = PlainData::new (&ibcd.data[..]);
            self.logger.debug (format! ("Relaying {} bytes to {:?}", data.data.len (), ibcd.component));
            match ibcd.component {
                Component::Neighborhood => DispatcherReal::receive_client (&mut self.neighborhood, source, data),
                Component::Hopper => DispatcherReal::receive_client (&mut self.hopper, source, data),
                Component::ProxyServer => panic! ("This should have been replaced with actorized ProxyServer"),
                Component::ProxyClient => DispatcherReal::receive_client (&mut self.proxy_client, source, data)
            }
        }
    }

    fn bind_client<C>(client: &Option<Arc<Mutex<C>>>, component: Component, transmitter: &mut Box<Transmitter>,
                      outbound_tx: &Sender<OutboundClientData>, clients: &PeerClients)
        where C: DispatcherClient + ?Sized {
        let handle = transmitter.make_handle(component, outbound_tx);
        let mut c = client.as_ref ().expect ("Internal error").as_ref ().lock ().expect("Internal error");
        c.bind(Box::new(handle), clients);
    }

    fn receive_client<C>(client_wrapper: &mut Option<Arc<Mutex<C>>>, source: Endpoint, data: PlainData)
        where C: DispatcherClient + ? Sized {
        let mut client = client_wrapper.as_ref ().expect ("Internal error").lock ().expect("Internal error");
        client.receive(source, data)
    }

    fn parse_args (args: &Vec<String>) -> DispatcherConfig {
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
        DispatcherConfig {
            dns_servers: dns_server_addrs
        }
    }
}

struct DispatcherConfig {
    dns_servers: Vec<SocketAddr>
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
    use std::sync::mpsc::Receiver;
    use std::net::SocketAddr;
    use std::marker::Sync;
    use std::str::FromStr;
    use std::ops::Deref;
    use std::ops::DerefMut;
    use actix::Actor;
    use sub_lib::test_utils::FakeStreamHolder;
    use sub_lib::test_utils::TestLog;
    use transmitter::TransmitterHandleReal;
    use sub_lib::stream_handler_pool::AddStreamMsg;
    use discriminator::DiscriminatorFactory;
    use sub_lib::dispatcher::InboundClientData;
    use test_utils::TcpStreamWrapperMock;
    use test_utils::HopperNull;
    use test_utils::NeighborhoodNull;
    use test_utils::ProxyClientNull;
    use test_utils::TestLogOwner;
    use test_utils::extract_log;
    use sub_lib::test_utils::Recorder;
    use sub_lib::test_utils::Recording;
    use sub_lib::test_utils::RecordAwaiter;
    use sub_lib::proxy_server::ProxyServerSubs;
    use sub_lib::hopper::HopperSubs;
    use sub_lib::actor_messages::BindMessage;
    use sub_lib::actor_messages::PeerActors;
    use sub_lib::test_utils::make_dispatcher_subs_from;
    use sub_lib::test_utils::make_proxy_server_subs_from;
    use sub_lib::test_utils::make_hopper_subs_from;
    use sub_lib::test_utils::make_stream_handler_pool_subs_from;

    struct ClientFactoryMock {
        neighborhood_mock: RefCell<Option<NeighborhoodNull>>,
        hopper_mock: RefCell<Option<HopperNull>>,
        proxy_client_mock: RefCell<Option<ProxyClientNull>>,
        proxy_client_dns_servers: Arc<Mutex<Vec<SocketAddr>>>
    }

    impl ClientFactory for ClientFactoryMock {
        fn make_neighborhood(&self) -> Arc<Mutex<Neighborhood>> {
            Arc::new (Mutex::new (self.neighborhood_mock.borrow_mut ().take ().unwrap ()))
        }

        fn make_hopper(&self) -> Arc<Mutex<Hopper>> {
            Arc::new (Mutex::new (self.hopper_mock.borrow_mut ().take ().unwrap ()))
        }

        fn make_proxy_client(&self, dns_servers: Vec<SocketAddr>) -> Arc<Mutex<ProxyClient>> {
            self.proxy_client_dns_servers.lock ().unwrap ().extend (dns_servers);
            Arc::new (Mutex::new (self.proxy_client_mock.borrow_mut ().take ().unwrap ()))
        }
    }

    impl ClientFactoryMock {
        fn from (neighborhood: NeighborhoodNull, hopper: HopperNull, proxy_client: ProxyClientNull) -> ClientFactoryMock {
            ClientFactoryMock {
                neighborhood_mock: RefCell::new (Some (neighborhood)),
                hopper_mock: RefCell::new (Some (hopper)),
                proxy_client_mock: RefCell::new (Some (proxy_client)),
                proxy_client_dns_servers: Arc::new (Mutex::new (vec! ()))
            }
        }
    }

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

    struct TransmitterNull {
        obcd_receiver: Receiver<OutboundClientData>,
        transmit_sub: Box<Subscriber<TransmitDataMsg> + Send>,
        to_test_tx: Sender<OutboundClientData>,
        limiter: Limiter
    }

    impl Transmitter for TransmitterNull {
        fn make_handle(&mut self, component: Component,
                       data_sender: &Sender<OutboundClientData>) -> TransmitterHandleReal {
            let result = TransmitterHandleReal::new (component, data_sender);
            result
        }

        fn handle_traffic(&mut self) {
            while self.limiter.should_continue () {
                let data = self.obcd_receiver.recv ().unwrap ();
                self.to_test_tx.send (data).unwrap ();
            }
        }
    }

    impl TransmitterNull {
        pub fn new (obcd_receiver: Receiver<OutboundClientData>,
                    transmit_sub: Box<Subscriber<TransmitDataMsg> + Send>,
                    to_test_tx: Sender<OutboundClientData>,limit: i32) -> TransmitterNull {
            TransmitterNull {
                obcd_receiver,
                transmit_sub,
                to_test_tx,
                limiter: Limiter::with_only (limit)
            }
        }
    }

    struct TransmitterFactoryNull {
        limit: i32,
        data_sender: RefCell<Option<Sender<OutboundClientData>>>
    }

    impl TransmitterFactory for TransmitterFactoryNull {
        fn make(&self, obcd_receiver: Receiver<OutboundClientData>,
                transmit_sub: Box<Subscriber<TransmitDataMsg> + Send>,
                _neighborhood_arc: Arc<Mutex<Neighborhood>>) -> Box<Transmitter> {
            Box::new (TransmitterNull::new (obcd_receiver, transmit_sub,
                self.data_sender.borrow_mut ().take ().unwrap (), self.limit))
        }
    }

    impl TransmitterFactoryNull {
        pub fn new (data_sender: Sender<OutboundClientData>, limit: i32) -> TransmitterFactoryNull {
            TransmitterFactoryNull {data_sender: RefCell::new (Some (data_sender)), limit}
        }
    }

    #[test]
    fn knows_its_name () {
        let subject = DispatcherBuilder::new ().build ();

        let result = subject.name ();

        assert_eq! (result, String::from ("Dispatcher"));
    }

    #[test]
    fn initialize_as_root_makes_clients () {
        let mut subject = DispatcherBuilder::new ()
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .build ();

        subject.initialize_as_root (&vec! (), &mut FakeStreamHolder::new ().streams ());

        assert_eq! (subject.neighborhood.is_some (), true);
        assert_eq! (subject.hopper.is_some (), true);
        assert_eq! (subject.proxy_client.is_some (), true);
    }

    #[test]
    // TODO: Add 443 to this test
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

        assert_eq! (first_handler_log.lock ().unwrap ().dump (), vec! ("bind_port_and_discriminator_factories (80, ...)"));
        assert_eq! (second_handler_log.lock ().unwrap ().dump ().len (), 0);
        assert_eq! (third_handler_log.lock ().unwrap ().dump ().len (), 0);
    }

    #[test]
    fn initialize_as_root_passes_dns_servers_parameter_to_proxy_client () {
        let neighborhood = NeighborhoodNull::new (vec! ());
        let hopper = HopperNull::new ();
        let proxy_client = ProxyClientNull::new ();
        let client_factory = ClientFactoryMock::from (neighborhood, hopper, proxy_client);
        let dns_servers_arc = client_factory.proxy_client_dns_servers.clone ();
        let mut subject = DispatcherBuilder::new ()
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .client_factory(client_factory)
            .build ();

        subject.initialize_as_root(&vec! (String::from ("--dns_servers"), String::from ("1.2.3.4,2.3.4.5")),
                                   &mut FakeStreamHolder::new ().streams ());

        let dns_servers_guard = dns_servers_arc.lock ().unwrap ();
        assert_eq! (dns_servers_guard.deref (),
                    &vec! (SocketAddr::from_str ("1.2.3.4:53").unwrap (), SocketAddr::from_str ("2.3.4.5:53").unwrap ()))
    }

    #[test]
    #[should_panic (expected = "Cannot use 'booga' as a DNS server IP address")]
    fn initialize_as_root_complains_about_dns_servers_syntax_errors () {
        let neighborhood = NeighborhoodNull::new (vec! ());
        let hopper = HopperNull::new ();
        let proxy_client = ProxyClientNull::new ();
        let client_factory = ClientFactoryMock::from (neighborhood, hopper, proxy_client);
        let mut subject = DispatcherBuilder::new ()
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Ok (())))
            .client_factory(client_factory)
            .build ();

        subject.initialize_as_root(&vec! (String::from ("--dns_servers"), String::from ("booga,booga")),
                                   &mut FakeStreamHolder::new ().streams ());
    }

    #[test]
    #[should_panic (expected = "Could not listen on port 80: address in use")]
    fn initialize_as_root_panics_if_tcp_listener_doesnt_bind () {
        let mut subject = DispatcherBuilder::new ()
            .add_listener_handler (ListenerHandlerNull::new (vec! ()).bind_port_result(Err (Error::from (ErrorKind::AddrInUse))))
            .build ();

        subject.initialize_as_root(&vec! (), &mut FakeStreamHolder::new ().streams ());
    }

    #[test]
    fn serve_without_root_moves_streams_from_listener_handlers_to_stream_handler_pool () {
        let first_message = AddStreamMsg {stream: Box::new (TcpStreamWrapperMock::new ().name ("first"))};
        let second_message = AddStreamMsg {stream: Box::new (TcpStreamWrapperMock::new ().name ("second"))};
        let third_message = AddStreamMsg {stream: Box::new (TcpStreamWrapperMock::new ().name ("third"))};
        let one_listener_handler = ListenerHandlerNull::new (vec! (
            first_message, second_message
        )).bind_port_result (Ok (()));
        let another_listener_handler = ListenerHandlerNull::new (vec! (
            third_message
        )).bind_port_result (Ok (()));
        let mut actor_system_factory = ActorSystemFactoryMock::with_two_recorders();
        let awaiter = actor_system_factory.stream_handler_pool_cluster.awaiter.take ().unwrap ();
        let recording_arc = actor_system_factory.stream_handler_pool_cluster.recording.take ().unwrap ();
        let mut subject = DispatcherBuilder::new ()
            .actor_system_factory (Box::new (actor_system_factory))
            .add_listener_handler (one_listener_handler)
            .add_listener_handler (another_listener_handler)
            .neighborhood (NeighborhoodNull::new (vec! ()))
            .incoming_limit (0)
            .build ();
        subject.initialize_as_root(&vec! (), &mut FakeStreamHolder::new ().streams ());

        subject.serve_without_root();

        let number_of_expected_messages_that_will_be_3_when_443_is_implemented = 2;
        awaiter.await_message_count (number_of_expected_messages_that_will_be_3_when_443_is_implemented);
        let recording = recording_arc.lock ().unwrap ();
        assert_eq! (recording.len (), number_of_expected_messages_that_will_be_3_when_443_is_implemented);
        let actual_names: Vec<String> = (0..number_of_expected_messages_that_will_be_3_when_443_is_implemented).into_iter().map (|i| {
            let pptr = &recording.get_record::<AddStreamMsg> (i).stream as *const _;
            unsafe {
                let tptr = pptr as *const Box<TcpStreamWrapperMock>;
                let stream = &*tptr;
                stream.name.clone ()
            }
        }).collect ();
        assert_eq! (actual_names.contains (&String::from ("first")), true, "{:?} does not contain 'first'", actual_names);
        assert_eq! (actual_names.contains (&String::from ("second")), true, "{:?} does not contain 'second'", actual_names);
        //assert_eq! (actual_names.contains (&String::from ("third")), true, "{:?} does not contain 'third'", actual_names);
    }

    #[test]
    fn serve_without_root_dispatches_messages_to_regular_clients () {
        let one_listener_handler = ListenerHandlerNull::new (vec! ()).bind_port_result (Ok (()));
        let another_listener_handler = ListenerHandlerNull::new (vec! ()).bind_port_result (Ok (()));
        let actor_system_factory = ActorSystemFactoryMock::with_real_dispatcher_facade ();
        let ibcd_sub = actor_system_factory.dispatcher_facade_cluster.subs.ibcd_sub.clone ();
        let socket_addr_n = SocketAddr::from_str ("1.2.3.4:5678").unwrap ();
        let socket_addr_h = SocketAddr::from_str ("2.3.4.5:6789").unwrap ();
        let socket_addr_pc = SocketAddr::from_str ("4.5.6.7:8901").unwrap ();
        let neighborhood = NeighborhoodNull::new (vec! (
            ("1.2.3.4", &[5678], "NBHD key"), ("2.3.4.5", &[6789], "HOPR key"), ("4.5.6.7", &[8901], "PXCL key")
        ));
        let neighborhood_log = neighborhood.get_test_log();
        let hopper = HopperNull::new ();
        let hopper_log = hopper.get_test_log();
        let proxy_client = ProxyClientNull::new ();
        let proxy_client_log = proxy_client.get_test_log();
        let client_factory = ClientFactoryMock::from (neighborhood, hopper, proxy_client);
        let mut subject = DispatcherBuilder::new ()
            .actor_system_factory (Box::new (actor_system_factory))
            .add_listener_handler (one_listener_handler)
            .add_listener_handler (another_listener_handler)
            .incoming_limit (3)
            .client_factory (client_factory)
            .transmitter_factory (TransmitterFactoryNull::new (mpsc::channel ().0, 0))
            .build ();
        subject.initialize_as_root(&vec! (), &mut FakeStreamHolder::new ().streams ());

        let join_handle = thread::spawn (move || {subject.serve_without_root();});

        let expected_data = vec! (
            InboundClientData {socket_addr: socket_addr_n, component: Component::Neighborhood, data: Vec::from ("nbhd".as_bytes ())},
            InboundClientData {socket_addr: socket_addr_h, component: Component::Hopper, data: Vec::from ("hopr".as_bytes ())},
            InboundClientData {socket_addr: socket_addr_pc, component: Component::ProxyClient, data: Vec::from ("pxcl".as_bytes ())}
        );
        expected_data.iter ().for_each (|ibcd| {ibcd_sub.send (ibcd.clone ()).unwrap ();});
        join_handle.join ().unwrap ();
        assert_eq! (neighborhood_log.lock ().unwrap ().dump ()[2], "receive ('Key(NBHD key)', 'nbhd'");
        assert_eq! (hopper_log.lock ().unwrap ().dump ()[1], "receive ('Key(HOPR key)', 'hopr'");
        assert_eq! (proxy_client_log.lock ().unwrap ().dump ()[1], "receive ('Key(PXCL key)', 'pxcl'");
    }

    #[test]
    fn serve_without_root_dispatches_messages_to_proxy_server_as_actor_more_than_unit_style () {
        let one_listener_handler = ListenerHandlerNull::new (vec! ()).bind_port_result (Ok (()));
        let another_listener_handler = ListenerHandlerNull::new (vec! ()).bind_port_result (Ok (()));
        let mut actor_system_factory = ActorSystemFactoryMock::with_real_dispatcher_facade ();
        let ibcd_sub = actor_system_factory.dispatcher_facade_cluster.subs.ibcd_sub.clone ();
        let socket_addr_ps = SocketAddr::from_str ("3.4.5.6:7890").unwrap ();
        let socket_addr_pc = SocketAddr::from_str ("4.5.6.7:8901").unwrap ();
        let neighborhood = NeighborhoodNull::new (vec! (
            ("1.2.3.4", &[5678], "NBHD key"), ("2.3.4.5", &[6789], "HOPR key"), ("4.5.6.7", &[8901], "PXCL key")
        ));
        let hopper = HopperNull::new ();
        let recording_arc = actor_system_factory.proxy_server_cluster.recording.take ().unwrap ();;
        let awaiter = actor_system_factory.proxy_server_cluster.awaiter.take ().unwrap ();
        let proxy_client = ProxyClientNull::new ();
        let client_factory = ClientFactoryMock::from (neighborhood, hopper,  proxy_client);
        let mut subject = DispatcherBuilder::new ()
            .actor_system_factory (Box::new (actor_system_factory))
            .add_listener_handler (one_listener_handler)
            .add_listener_handler (another_listener_handler)
            .incoming_limit (1)
            .client_factory (client_factory)
            .transmitter_factory (TransmitterFactoryNull::new (mpsc::channel ().0, 0))
            .build ();
        subject.initialize_as_root(&vec! (), &mut FakeStreamHolder::new ().streams ());

        let join_handle = thread::spawn (move || {subject.serve_without_root();});

        let expected_data = vec! (
            InboundClientData {socket_addr: socket_addr_ps, component: Component::ProxyServer, data: Vec::from ("pxsv".as_bytes ())},
            InboundClientData {socket_addr: socket_addr_pc, component: Component::ProxyClient, data: Vec::from ("pxcl".as_bytes ())},
        );
        expected_data.iter ().for_each (|ibcd| {ibcd_sub.send (ibcd.clone ()).unwrap ();});
        join_handle.join ().unwrap ();

        awaiter.await_message_count (1);
        let recording = recording_arc.lock ().unwrap ();
        assert_eq! (recording.len (), 1);
        let message = &recording.get_record::<RequestMessage>(0) as *const _;
        let (actual_socket_addr, actual_component, actual_data) = unsafe {
            let tptr = message as *const Box<RequestMessage>;
            let message = &*tptr;
            message.data.clone ()
        };

        assert_eq!(actual_component, Component::ProxyServer);
        assert_eq!(actual_socket_addr, Endpoint::Socket(socket_addr_ps));
        assert_eq!(actual_data, Vec::from ("pxsv".as_bytes ()));
    }

    struct DispatcherFacadeCluster {
        #[allow (dead_code)]
        recording: Option<Arc<Mutex<Recording>>>,
        #[allow (dead_code)]
        awaiter: Option<RecordAwaiter>,
        subs: DispatcherFacadeSubs
    }

    struct StreamHandlerPoolCluster {
        recording: Option<Arc<Mutex<Recording>>>,
        awaiter: Option<RecordAwaiter>,
        subs: StreamHandlerPoolSubs
    }

    struct ProxyServerCluster {
        recording: Option<Arc<Mutex<Recording>>>,
        awaiter: Option<RecordAwaiter>,
        subs: ProxyServerSubs,
    }

    struct HopperFacadeCluster {
        _recording: Option<Arc<Mutex<Recording>>>,
        _awaiter: Option<RecordAwaiter>,
        subs: HopperSubs,
    }

    struct ActorSystemFactoryMock {
        stream_handler_pool_cluster: StreamHandlerPoolCluster,
        dispatcher_facade_cluster: DispatcherFacadeCluster,
        proxy_server_cluster: ProxyServerCluster,
        _hopper_facade_cluster: HopperFacadeCluster,
        ibcd_receiver_cell: RefCell<Option<Receiver<InboundClientData>>>
    }

    impl ActorSystemFactory for ActorSystemFactoryMock {
        fn make_and_start_actors(&self, ibcd_transmitter: Sender<InboundClientData>, _hopper: Arc<Mutex<Hopper>>) -> (DispatcherFacadeSubs, StreamHandlerPoolSubs) {
            let mut ibcd_receiver_opt_ref = self.ibcd_receiver_cell.borrow_mut ();
            let ibcd_receiver_opt = ibcd_receiver_opt_ref.deref_mut ();
            if ibcd_receiver_opt.is_some () {
                let ibcd_receiver = ibcd_receiver_opt.take ().unwrap ();
                // Buckle this transmitter to the receiver created earlier during with_real_dispatcher_facade ()
                thread::spawn (move || {
                    loop {
                        match ibcd_receiver.recv () {
                            Ok (msg) => ibcd_transmitter.send (msg).unwrap (),
                            Err (_) => break
                        };
                    }
                });
            }

            (self.dispatcher_facade_cluster.subs.clone (), self.stream_handler_pool_cluster.subs.clone ())
        }
    }

    impl ActorSystemFactoryMock {
        fn with_two_recorders() -> ActorSystemFactoryMock {
            let (tx, rx) = mpsc::channel ();
            thread::spawn (move || {
                let system = System::new ("test");

                let dispatcher_facade_cluster = {
                    let dispatcher_facade = Recorder::new();
                    let recording = dispatcher_facade.get_recording();
                    let awaiter = dispatcher_facade.get_awaiter();
                    let addr: SyncAddress<_> = dispatcher_facade.start();
                    DispatcherFacadeCluster {
                        recording: Some (recording),
                        awaiter: Some (awaiter),
                        subs: make_dispatcher_subs_from(&addr)
                    }
                };

                let stream_handler_pool_cluster = {
                    let stream_handler_pool = Recorder::new();
                    let recording = stream_handler_pool.get_recording();
                    let awaiter = stream_handler_pool.get_awaiter();
                    let addr: SyncAddress<_> = stream_handler_pool.start();
                    StreamHandlerPoolCluster {
                        recording: Some (recording),
                        awaiter: Some (awaiter),
                        subs: make_stream_handler_pool_subs_from(&addr)
                    }
                };

                let proxy_server_cluster = {
                    let proxy_server = Recorder::new();
                    let recording = proxy_server.get_recording();
                    let awaiter = proxy_server.get_awaiter();
                    let addr: SyncAddress<_> = proxy_server.start();
                    ProxyServerCluster {
                        recording: Some(recording),
                        awaiter: Some(awaiter),
                        subs: make_proxy_server_subs_from(&addr)
                    }
                };

                let hopper_facade_cluster = {
                    let hopper = Recorder::new();
                    let recording = hopper.get_recording();
                    let awaiter = hopper.get_awaiter();
                    let addr: SyncAddress<_> = hopper.start();
                    HopperFacadeCluster {
                        _recording: Some(recording),
                        _awaiter: Some(awaiter),
                        subs: make_hopper_subs_from(&addr)
                    }
                };

                tx.send ((dispatcher_facade_cluster, stream_handler_pool_cluster, proxy_server_cluster, hopper_facade_cluster)).unwrap ();
                system.run ();
            });
            let (dispatcher_facade_cluster, stream_handler_pool_cluster, proxy_server_cluster, hopper_facade_cluster) = rx.recv ().unwrap ();
            ActorSystemFactoryMock {
                dispatcher_facade_cluster,
                stream_handler_pool_cluster,
                proxy_server_cluster,
                _hopper_facade_cluster: hopper_facade_cluster,
                ibcd_receiver_cell: RefCell::new (None)
            }
        }

        fn with_real_dispatcher_facade () -> ActorSystemFactoryMock {
            let (tx, rx) = mpsc::channel ();
            let (ibcd_transmitter, ibcd_receiver) = mpsc::channel ();
            thread::spawn (move || {
                let system = System::new ("test");

                let dispatcher_facade_cluster = {
                    let dispatcher_facade = DispatcherFacade::new (ibcd_transmitter);
                    let addr: SyncAddress<_> = dispatcher_facade.start();
                    DispatcherFacadeCluster {
                        recording: None,
                        awaiter: None,
                        subs: DispatcherFacade::make_subs_from(&addr)
                    }
                };

                let stream_handler_pool_cluster = {
                    let stream_handler_pool = Recorder::new();
                    let recording = stream_handler_pool.get_recording();
                    let awaiter = stream_handler_pool.get_awaiter();
                    let addr: SyncAddress<_> = stream_handler_pool.start();
                    StreamHandlerPoolCluster {
                        recording: Some (recording),
                        awaiter: Some (awaiter),
                        subs: make_stream_handler_pool_subs_from(&addr)
                    }
                };

                let proxy_server_cluster = {
                    let proxy_server = Recorder::new();
                    let recording = proxy_server.get_recording();
                    let awaiter = proxy_server.get_awaiter();
                    let addr: SyncAddress<_> = proxy_server.start();
                    ProxyServerCluster {
                        recording: Some(recording),
                        awaiter: Some(awaiter),
                        subs: make_proxy_server_subs_from(&addr)
                    }
                };

                let hopper_facade_cluster = {
                    let hopper = Recorder::new();
                    let recording = hopper.get_recording();
                    let awaiter = hopper.get_awaiter();
                    let addr: SyncAddress<_> = hopper.start();
                    HopperFacadeCluster {
                        _recording: Some(recording),
                        _awaiter: Some(awaiter),
                        subs: make_hopper_subs_from(&addr)
                    }
                };

                dispatcher_facade_cluster.subs.bind.send(BindMessage { peer_actors: PeerActors {
                    proxy_server: proxy_server_cluster.subs.clone(),
                    dispatcher: dispatcher_facade_cluster.subs.clone(),
                    hopper: hopper_facade_cluster.subs.clone(),
                    stream_handler_pool: stream_handler_pool_cluster.subs.clone(),
                } });

                tx.send ((dispatcher_facade_cluster, stream_handler_pool_cluster, proxy_server_cluster, hopper_facade_cluster)).unwrap ();
                system.run ();
            });
            let (dispatcher_facade_cluster, stream_handler_pool_cluster, proxy_server_cluster, hopper_facade_cluster) = rx.recv ().unwrap ();
            ActorSystemFactoryMock {
                dispatcher_facade_cluster,
                stream_handler_pool_cluster,
                proxy_server_cluster,
                _hopper_facade_cluster: hopper_facade_cluster,
                ibcd_receiver_cell: RefCell::new (Some (ibcd_receiver))
            }
        }
    }

    struct DispatcherBuilder {
        configuration: Option<Configuration>,
        actor_system_factory: Box<ActorSystemFactory>,
        #[allow (dead_code)]
        dispatcher_facade_cluster: Option<DispatcherFacadeCluster>,
        stream_handler_pool_cluster: Option<StreamHandlerPoolCluster>,
        client_factory: Option<ClientFactoryMock>,
        listener_handler_factory: ListenerHandlerFactoryMock,
        transmitter_factory: TransmitterFactoryNull,
        neighborhood: NeighborhoodNull,
        hopper: HopperNull,
        proxy_client: ProxyClientNull,
        incoming_limit: Option<i32>
    }

    impl DispatcherBuilder {
        fn new () -> DispatcherBuilder {
            let mut neighborhood = NeighborhoodNull::new (vec! ());
            neighborhood.bound = true;
            DispatcherBuilder {
                configuration: None,
                actor_system_factory: Box::new (ActorSystemFactoryMock::with_two_recorders()),
                dispatcher_facade_cluster: None,
                stream_handler_pool_cluster: None,
                client_factory: None,
                // Don't modify this line unless you've already looked at DispatcherBuilder::add_listener_handler().
                listener_handler_factory: ListenerHandlerFactoryMock::new (),
                transmitter_factory: TransmitterFactoryNull::new (mpsc::channel ().0, 100),
                neighborhood,
                hopper: HopperNull::new (),
                proxy_client: ProxyClientNull::new (),
                incoming_limit: None
            }
        }

        #[allow (dead_code)]
        fn configuration (mut self, configuration: Configuration) -> DispatcherBuilder {
            self.configuration = Some (configuration);
            self
        }

        #[allow (dead_code)]
        fn actor_system_factory (mut self, actor_system_factory: Box<ActorSystemFactory>) -> DispatcherBuilder {
            self.actor_system_factory = actor_system_factory;
            self
        }

        #[allow (dead_code)]
        fn client_factory (mut self, client_factory: ClientFactoryMock) -> DispatcherBuilder {
            self.client_factory = Some (client_factory);
            self
        }

        #[allow (dead_code)]
        fn add_listener_handler (mut self, listener_handler: ListenerHandlerNull) -> DispatcherBuilder {
            self.listener_handler_factory.add (listener_handler);
            self
        }

        #[allow (dead_code)]
        fn transmitter_factory (mut self, transmitter_factory: TransmitterFactoryNull) -> DispatcherBuilder {
            self.transmitter_factory = transmitter_factory;
            self
        }

        #[allow (dead_code)]
        fn neighborhood (mut self, neighborhood: NeighborhoodNull) -> DispatcherBuilder {
            self.neighborhood = neighborhood;
            self
        }

        #[allow (dead_code)]
        fn hopper (mut self, client: HopperNull) -> DispatcherBuilder {
            self.hopper = client;
            self
        }

        #[allow (dead_code)]
        fn proxy_client (mut self, client: ProxyClientNull) -> DispatcherBuilder {
            self.proxy_client = client;
            self
        }

        #[allow (dead_code)]
        fn incoming_limit (mut self, limit: i32) -> DispatcherBuilder {
            self.incoming_limit = Some (limit);
            self
        }

        #[allow (dead_code)]
        fn build (self) -> DispatcherReal {
            let stream_handler_pool_subs = match &self.stream_handler_pool_cluster {
                &Some (ref shpc) => Some (shpc.subs.clone ()),
                &None => None
            };
            DispatcherReal {
                actor_system_factory: self.actor_system_factory,
                stream_handler_pool_subs,
                client_factory: if self.client_factory.is_some () {
                    Box::new (self.client_factory.unwrap ())
                }
                else {
                    Box::new (ClientFactoryMock::from (
                        self.neighborhood,
                        self.hopper,
                        self.proxy_client
                    ))
                },
                listener_handler_factory: Box::new (self.listener_handler_factory),
                transmitter_factory: Box::new (self.transmitter_factory),
                neighborhood: None, hopper: None, proxy_client: None,
                listener_handlers: vec! (),
                incoming_limiter: if self.incoming_limit.is_some () {
                    Limiter::with_only (self.incoming_limit.unwrap ())
                }
                else {
                    Limiter::new ()
                },
                logger: Logger::new ("Dispatcher"),
            }
        }
    }
}
