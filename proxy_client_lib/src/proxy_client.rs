// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use actix::Syn;
use resolver_wrapper::ResolverWrapperFactory;
use resolver_wrapper::ResolverWrapperFactoryReal;
use std::net::SocketAddr;
use stream_handler_pool::StreamHandlerPool;
use stream_handler_pool::StreamHandlerPoolFactory;
use stream_handler_pool::StreamHandlerPoolFactoryReal;
use sub_lib::cryptde::CryptDE;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::peer_actors::BindMessage;
use sub_lib::proxy_client::ProxyClientSubs;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::utils::NODE_MAILBOX_CAPACITY;
use trust_dns_resolver::config::NameServerConfig;
use trust_dns_resolver::config::Protocol;
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::config::ResolverOpts;

pub struct ProxyClient {
    dns_servers: Vec<SocketAddr>,
    resolver_wrapper_factory: Box<ResolverWrapperFactory>,
    stream_handler_pool_factory: Box<StreamHandlerPoolFactory>,
    _cryptde: &'static CryptDE, // This is not used now, but a version of it may be used in the future when ser/de and en/decrypt are combined.
    to_hopper: Option<Recipient<Syn, IncipientCoresPackage>>,
    pool: Option<Box<StreamHandlerPool>>,
    logger: Logger,
}

impl Actor for ProxyClient {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for ProxyClient {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        self.logger.debug(format!("Handling BindMessage"));
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.to_hopper = Some(msg.peer_actors.hopper.from_hopper_client.clone());
        let mut config = ResolverConfig::new();
        for dns_server_ref in &self.dns_servers {
            self.logger
                .info(format!("Adding DNS server: {}", dns_server_ref.ip()));
            config.add_name_server(NameServerConfig {
                socket_addr: *dns_server_ref,
                protocol: Protocol::Udp,
                tls_dns_name: None,
            })
        }
        let opts = ResolverOpts::default();
        let resolver = self.resolver_wrapper_factory.make(config, opts);
        self.pool = Some(self.stream_handler_pool_factory.make(
            resolver,
            self._cryptde,
            msg.peer_actors.hopper.from_hopper_client,
        ));
        ()
    }
}

impl Handler<ExpiredCoresPackage> for ProxyClient {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackage, _ctx: &mut Self::Context) -> Self::Result {
        let payload = match msg.payload::<ClientRequestPayload>() {
            Ok(payload) => payload,
            Err(e) => {
                self.logger.error(format!(
                    "Error ('{}') interpreting payload for transmission: {:?}",
                    e,
                    msg.payload_data().data
                ));
                return ();
            }
        };
        let return_route = msg.remaining_route;
        let pool = self.pool.as_mut().expect("StreamHandlerPool unbound");
        pool.process_package(payload, return_route);
        self.logger.debug(format!("ExpiredCoresPackage handled"));
        ()
    }
}

impl ProxyClient {
    pub fn new(cryptde: &'static CryptDE, dns_servers: Vec<SocketAddr>) -> ProxyClient {
        if dns_servers.is_empty() {
            panic! ("Proxy Client requires at least one DNS server IP address after the --dns_servers parameter")
        }
        ProxyClient {
            dns_servers,
            resolver_wrapper_factory: Box::new(ResolverWrapperFactoryReal {}),
            stream_handler_pool_factory: Box::new(StreamHandlerPoolFactoryReal {}),
            _cryptde: cryptde,
            to_hopper: None,
            pool: None,
            logger: Logger::new("Proxy Client"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Syn, ProxyClient>) -> ProxyClientSubs {
        ProxyClientSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            from_hopper: addr.clone().recipient::<ExpiredCoresPackage>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Arbiter;
    use actix::Recipient;
    use actix::System;
    use local_test_utils::ResolverWrapperFactoryMock;
    use local_test_utils::ResolverWrapperMock;
    use resolver_wrapper::ResolverWrapper;
    use serde_cbor;
    use std::cell::RefCell;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use stream_handler_pool::StreamHandlerPool;
    use stream_handler_pool::StreamHandlerPoolFactory;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde::PlainData;
    use sub_lib::proxy_server::ClientRequestPayload;
    use sub_lib::proxy_server::ProxyProtocol;
    use sub_lib::route::Route;
    use sub_lib::sequence_buffer::SequencedPacket;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::recorder::make_peer_actors;
    use test_utils::recorder::make_peer_actors_from;
    use test_utils::recorder::Recorder;
    use test_utils::test_utils;
    use test_utils::test_utils::cryptde;
    use test_utils::test_utils::make_meaningless_stream_key;

    fn dnss() -> Vec<SocketAddr> {
        vec![SocketAddr::from_str("8.8.8.8:53").unwrap()]
    }

    pub struct StreamHandlerPoolMock {
        process_package_parameters: Arc<Mutex<Vec<(ClientRequestPayload, Route)>>>,
    }

    impl StreamHandlerPool for StreamHandlerPoolMock {
        fn process_package(&mut self, payload: ClientRequestPayload, route: Route) {
            self.process_package_parameters
                .lock()
                .unwrap()
                .push((payload, route));
        }
    }

    impl StreamHandlerPoolMock {
        pub fn new() -> StreamHandlerPoolMock {
            StreamHandlerPoolMock {
                process_package_parameters: Arc::new(Mutex::new(vec![])),
            }
        }

        pub fn process_package_parameters(
            self,
            parameters: &mut Arc<Mutex<Vec<(ClientRequestPayload, Route)>>>,
        ) -> StreamHandlerPoolMock {
            *parameters = self.process_package_parameters.clone();
            self
        }
    }

    pub struct StreamHandlerPoolFactoryMock {
        make_parameters: Arc<
            Mutex<
                Vec<(
                    Box<ResolverWrapper>,
                    &'static CryptDE,
                    Recipient<Syn, IncipientCoresPackage>,
                )>,
            >,
        >,
        make_results: RefCell<Vec<Box<StreamHandlerPool>>>,
    }

    impl StreamHandlerPoolFactory for StreamHandlerPoolFactoryMock {
        fn make(
            &self,
            resolver: Box<ResolverWrapper>,
            cryptde: &'static CryptDE,
            hopper_sub: Recipient<Syn, IncipientCoresPackage>,
        ) -> Box<StreamHandlerPool> {
            self.make_parameters
                .lock()
                .unwrap()
                .push((resolver, cryptde, hopper_sub));
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl StreamHandlerPoolFactoryMock {
        pub fn new() -> StreamHandlerPoolFactoryMock {
            StreamHandlerPoolFactoryMock {
                make_parameters: Arc::new(Mutex::new(vec![])),
                make_results: RefCell::new(vec![]),
            }
        }

        pub fn make_parameters(
            self,
            parameters: &mut Arc<
                Mutex<
                    Vec<(
                        Box<ResolverWrapper>,
                        &'static CryptDE,
                        Recipient<Syn, IncipientCoresPackage>,
                    )>,
                >,
            >,
        ) -> StreamHandlerPoolFactoryMock {
            *parameters = self.make_parameters.clone();
            self
        }

        pub fn make_result(self, result: Box<StreamHandlerPool>) -> StreamHandlerPoolFactoryMock {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    #[should_panic(
        expected = "Proxy Client requires at least one DNS server IP address after the --dns_servers parameter"
    )]
    fn at_least_one_dns_server_must_be_provided() {
        ProxyClient::new(cryptde(), vec![]);
    }

    #[test]
    fn bind_operates_properly() {
        let system = System::new("bind_initializes_resolver_wrapper_properly");
        let resolver_wrapper = ResolverWrapperMock::new();
        let mut new_parameters: Arc<Mutex<Vec<(ResolverConfig, ResolverOpts)>>> =
            Arc::new(Mutex::new(vec![]));
        let resolver_wrapper_factory = ResolverWrapperFactoryMock::new()
            .new_parameters(&mut new_parameters)
            .new_result(Box::new(resolver_wrapper));
        let pool = StreamHandlerPoolMock::new();
        let mut pool_factory_make_parameters = Arc::new(Mutex::new(vec![]));
        let pool_factory = StreamHandlerPoolFactoryMock::new()
            .make_parameters(&mut pool_factory_make_parameters)
            .make_result(Box::new(pool));
        let peer_actors = make_peer_actors();
        let mut subject = ProxyClient::new(
            cryptde(),
            vec![
                SocketAddr::from_str("4.3.2.1:4321").unwrap(),
                SocketAddr::from_str("5.4.3.2:5432").unwrap(),
            ],
        );
        subject.resolver_wrapper_factory = Box::new(resolver_wrapper_factory);
        subject.stream_handler_pool_factory = Box::new(pool_factory);
        let subject_addr: Addr<Syn, ProxyClient> = subject.start();

        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();

        let mut new_parameters_guard = new_parameters.lock().unwrap();
        let (config, opts) = new_parameters_guard.remove(0);
        assert_eq!(config.domain(), None);
        assert_eq!(config.search(), &[]);
        assert_eq!(
            config.name_servers(),
            &[
                NameServerConfig {
                    socket_addr: SocketAddr::from_str("4.3.2.1:4321").unwrap(),
                    protocol: Protocol::Udp,
                    tls_dns_name: None
                },
                NameServerConfig {
                    socket_addr: SocketAddr::from_str("5.4.3.2:5432").unwrap(),
                    protocol: Protocol::Udp,
                    tls_dns_name: None
                },
            ]
        );
        assert_eq!(opts, ResolverOpts::default());
        assert_eq!(new_parameters_guard.is_empty(), true);
    }

    #[test]
    #[should_panic(expected = "StreamHandlerPool unbound")]
    fn panics_if_unbound() {
        let request = ClientRequestPayload {
            stream_key: make_meaningless_stream_key(),
            sequenced_packet: SequencedPacket {
                data: b"HEAD http://www.nyan.cat/ HTTP/1.1\r\n\r\n".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: Some(String::from("target.hostname.com")),
            target_port: 1234,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"originator_public_key"[..]),
        };
        let cryptde = cryptde();
        let package = ExpiredCoresPackage::new(
            test_utils::route_to_proxy_client(&cryptde.public_key(), cryptde),
            PlainData::new(&serde_cbor::ser::to_vec(&request.clone()).unwrap()[..]),
        );
        let system = System::new("panics_if_hopper_is_unbound");
        let subject = ProxyClient::new(cryptde, dnss());
        let subject_addr: Addr<Syn, ProxyClient> = subject.start();

        subject_addr.try_send(package).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }

    #[test]
    fn invalid_package_is_logged_and_discarded() {
        init_test_logging();
        let package = ExpiredCoresPackage::new(
            test_utils::make_meaningless_route(),
            PlainData::new(&b"invalid"[..]),
        );
        let system = System::new("invalid_package_is_logged_and_discarded");
        let subject = ProxyClient::new(cryptde(), dnss());
        let addr: Addr<Syn, ProxyClient> = subject.start();
        let peer_actors = make_peer_actors_from(None, None, None, None, None);
        addr.try_send(BindMessage { peer_actors }).unwrap();

        addr.try_send(package).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        TestLogHandler::new ().await_log_containing("ERROR: Proxy Client: Error ('EOF while parsing a value at offset 7') interpreting payload for transmission: [105, 110, 118, 97, 108, 105, 100]", 1000);
    }

    #[test]
    fn data_from_hopper_is_relayed_to_stream_handler_pool() {
        let request = ClientRequestPayload {
            stream_key: make_meaningless_stream_key(),
            sequenced_packet: SequencedPacket {
                data: b"inbound data".to_vec(),
                sequence_number: 0,
                last_data: false,
            },
            target_hostname: None,
            target_port: 0,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&b"originator"[..]),
        };
        let package = ExpiredCoresPackage::new(
            test_utils::make_meaningless_route(),
            PlainData::new(&serde_cbor::ser::to_vec(&request.clone()).unwrap()[..]),
        );
        let hopper = Recorder::new();

        let system = System::new("unparseable_request_results_in_log_and_no_response");
        let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
        let mut process_package_parameters = Arc::new(Mutex::new(vec![]));
        let pool = Box::new(
            StreamHandlerPoolMock::new()
                .process_package_parameters(&mut process_package_parameters),
        );
        let pool_factory = StreamHandlerPoolFactoryMock::new().make_result(pool);
        let resolver = ResolverWrapperMock::new()
            .lookup_ip_success(vec![IpAddr::from_str("4.3.2.1").unwrap()]);
        let resolver_factory = ResolverWrapperFactoryMock::new().new_result(Box::new(resolver));
        let mut subject = ProxyClient::new(cryptde(), dnss());
        subject.resolver_wrapper_factory = Box::new(resolver_factory);
        subject.stream_handler_pool_factory = Box::new(pool_factory);
        let subject_addr: Addr<Syn, ProxyClient> = subject.start();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(package).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        let parameter = process_package_parameters.lock().unwrap().remove(0);
        assert_eq!(parameter, (request, test_utils::make_meaningless_route()));
    }
}
