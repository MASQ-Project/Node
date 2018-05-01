// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use actix::Actor;
use actix::Arbiter;
use actix::Context;
use actix::Handler;
use actix::Subscriber;
use actix::SyncAddress;
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::config::NameServerConfig;
use trust_dns_resolver::config::Protocol;
use sub_lib::cryptde::CryptDE;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::peer_actors::BindMessage;
use sub_lib::proxy_client::ProxyClientSubs;
use sub_lib::tcp_wrappers::TcpStreamWrapperFactory;
use sub_lib::tcp_wrappers::TcpStreamWrapperFactoryReal;
use stream_handler_pool::StreamHandlerPool;
use stream_handler_pool::StreamHandlerPoolFactory;
use resolver_wrapper::ResolverWrapperFactory;
use resolver_wrapper::ResolverWrapperFactoryReal;
use stream_handler_pool::StreamHandlerPoolFactoryReal;
use sub_lib::logger::Logger;

pub struct ProxyClient {
    dns_servers: Vec<SocketAddr>,
    tcp_stream_wrapper_factory: Box<TcpStreamWrapperFactory>,
    resolver_wrapper_factory: Box<ResolverWrapperFactory>,
    stream_handler_pool_factory: Box<StreamHandlerPoolFactory>,
    cryptde: Option<Box<CryptDE>>,
    to_hopper: Option<Box<Subscriber<IncipientCoresPackage> + Send>>,
    pool: Option<Box<StreamHandlerPool>>,
    logger: Logger,
}

impl Actor for ProxyClient {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for ProxyClient {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.logger.debug (format!("Handling BindMessage"));
        self.to_hopper = Some(msg.peer_actors.hopper.from_hopper_client.clone ());
        let mut config = ResolverConfig::new ();
        for dns_server_ref in &self.dns_servers {
            self.logger.info (format! ("Adding DNS server: {}", dns_server_ref.ip ()));
            config.add_name_server(NameServerConfig {
                socket_addr: *dns_server_ref,
                protocol: Protocol::Udp
            })
        }
        let opts = ResolverOpts::default ();
        let resolver = self.resolver_wrapper_factory.make(config, opts, Arbiter::handle ());
        // crashpoint - is cryptde even needed in the ProxyClient submodule?
        self.pool = Some (self.stream_handler_pool_factory.make (resolver,
            self.cryptde.take ().expect ("CryptDE unbound"), msg.peer_actors.hopper.from_hopper_client));
        ()
    }
}

impl Handler<ExpiredCoresPackage> for ProxyClient {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackage, _ctx: &mut Self::Context) -> Self::Result {
        let pool = self.pool.as_mut ().expect ("StreamHandlerPool unbound");
        pool.process_package (msg);
        self.logger.debug (format! ("ExpiredCoresPackage handled"));
        ()
    }
}

impl ProxyClient {
    pub fn new(cryptde: Box<CryptDE>, dns_servers: Vec<SocketAddr>) -> ProxyClient {
        if dns_servers.is_empty () {
            panic! ("Proxy Client requires at least one DNS server IP address after the --dns_servers parameter")
        }
        ProxyClient {
            dns_servers,
            tcp_stream_wrapper_factory: Box::new(TcpStreamWrapperFactoryReal {}),
            resolver_wrapper_factory: Box::new (ResolverWrapperFactoryReal {}),
            stream_handler_pool_factory: Box::new (StreamHandlerPoolFactoryReal {}),
            cryptde: Some (cryptde),
            to_hopper: None,
            pool: None,
            logger: Logger::new ("Proxy Client")
        }
    }

    pub fn make_subs_from(addr: &SyncAddress<ProxyClient>) -> ProxyClientSubs {
        ProxyClientSubs {
            bind: addr.subscriber::<BindMessage>(),
            from_hopper: addr.subscriber::<ExpiredCoresPackage>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::net::Shutdown;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;
    use actix::System;
    use actix::Arbiter;
    use actix::msgs;
    use serde_cbor;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde::PlainData;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::proxy_server::ClientRequestPayload;
    use sub_lib::proxy_server::ProxyProtocol;
    use test_utils::test_utils;
    use test_utils::test_utils::make_peer_actors;
    use test_utils::test_utils::make_peer_actors_from;
    use test_utils::test_utils::Recorder;
    use stream_handler_pool::StreamHandlerPool;
    use local_test_utils::TcpStreamWrapperMock;
    use local_test_utils::TcpStreamWrapperFactoryMock;
    use local_test_utils::ResolverWrapperFactoryMock;
    use local_test_utils::ResolverWrapperMock;
    use std::net::IpAddr;
    use stream_handler_pool::StreamHandlerPoolFactory;
    use resolver_wrapper::ResolverWrapper;
    use std::cell::RefCell;
    use tokio_core::reactor::CoreId;

    fn dnss () -> Vec<SocketAddr> {
        vec! (SocketAddr::from_str ("8.8.8.8:53").unwrap ())
    }

    pub struct StreamHandlerPoolMock {
        process_package_parameters: Arc<Mutex<Vec<ExpiredCoresPackage>>>,
    }

    impl StreamHandlerPool for StreamHandlerPoolMock {
        fn process_package(&mut self, package: ExpiredCoresPackage) {
            self.process_package_parameters.lock ().unwrap ().push (package);
        }
    }

    impl StreamHandlerPoolMock {
        pub fn new () -> StreamHandlerPoolMock {
            StreamHandlerPoolMock {
                process_package_parameters: Arc::new (Mutex::new (vec! ())),
            }
        }

        pub fn process_package_parameters (self, parameters: &mut Arc<Mutex<Vec<ExpiredCoresPackage>>>) -> StreamHandlerPoolMock {
            *parameters = self.process_package_parameters.clone ();
            self
        }
    }

    pub struct StreamHandlerPoolFactoryMock {
        make_parameters: Arc<Mutex<Vec<(Box<ResolverWrapper>, Box<CryptDE>, Box<Subscriber<IncipientCoresPackage> + Send>)>>>,
        make_results: RefCell<Vec<Box<StreamHandlerPool>>>
    }

    impl StreamHandlerPoolFactory for StreamHandlerPoolFactoryMock {
        fn make(&self, resolver: Box<ResolverWrapper>, cryptde: Box<CryptDE>,
                hopper_sub: Box<Subscriber<IncipientCoresPackage> + Send>) -> Box<StreamHandlerPool> {
            self.make_parameters.lock ().unwrap ().push ((resolver, cryptde, hopper_sub));
            self.make_results.borrow_mut ().remove (0)
        }
    }

    impl StreamHandlerPoolFactoryMock {
        pub fn new () -> StreamHandlerPoolFactoryMock {
            StreamHandlerPoolFactoryMock {
                make_parameters: Arc::new (Mutex::new (vec! ())),
                make_results: RefCell::new (vec! ())
            }
        }

        pub fn make_parameters (self, parameters: &mut Arc<Mutex<Vec<(Box<ResolverWrapper>, Box<CryptDE>,
                Box<Subscriber<IncipientCoresPackage> + Send>)>>>) -> StreamHandlerPoolFactoryMock {
            *parameters = self.make_parameters.clone ();
            self
        }

        pub fn make_result (self, result: Box<StreamHandlerPool>) -> StreamHandlerPoolFactoryMock {
            self.make_results.borrow_mut ().push (result);
            self
        }
    }

    #[test]
    #[should_panic (expected = "Proxy Client requires at least one DNS server IP address after the --dns_servers parameter")]
    fn at_least_one_dns_server_must_be_provided () {
        ProxyClient::new (Box::new (CryptDENull::new ()), vec! ());
    }

    #[test]
    fn bind_operates_properly () {
        let system = System::new("bind_initializes_resolver_wrapper_properly");
        let resolver_wrapper = ResolverWrapperMock::new ();
        let mut new_parameters: Arc<Mutex<Vec<(ResolverConfig, ResolverOpts, CoreId)>>> = Arc::new (Mutex::new (vec! ()));
        let resolver_wrapper_factory = ResolverWrapperFactoryMock::new ()
            .new_parameters (&mut new_parameters)
            .new_result (Box::new (resolver_wrapper));
        let pool = StreamHandlerPoolMock::new ();
        let mut pool_factory_make_parameters = Arc::new (Mutex::new (vec! ()));
        let pool_factory = StreamHandlerPoolFactoryMock::new ()
            .make_parameters (&mut pool_factory_make_parameters)
            .make_result (Box::new (pool));
        let peer_actors = make_peer_actors();
        let mut subject = ProxyClient::new (Box::new (CryptDENull::new ()), vec! (
            SocketAddr::from_str ("4.3.2.1:4321").unwrap (),
            SocketAddr::from_str ("5.4.3.2:5432").unwrap ()
        ));
        subject.resolver_wrapper_factory = Box::new (resolver_wrapper_factory);
        subject.stream_handler_pool_factory = Box::new (pool_factory);
        let subject_addr: SyncAddress<_> = subject.start();

        subject_addr.send(BindMessage { peer_actors });

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        let mut new_parameters_guard = new_parameters.lock ().unwrap ();
        let (config, opts, _) = new_parameters_guard.remove (0);
        assert_eq! (config.domain (), None);
        assert_eq! (config.search (), &[]);
        assert_eq! (config.name_servers (), &[
            NameServerConfig {socket_addr: SocketAddr::from_str ("4.3.2.1:4321").unwrap (), protocol: Protocol::Udp},
            NameServerConfig {socket_addr: SocketAddr::from_str ("5.4.3.2:5432").unwrap (), protocol: Protocol::Udp},
        ]);
        assert_eq! (opts, ResolverOpts::default ());
        assert_eq! (new_parameters_guard.is_empty (), true);
    }

    #[test]
    #[should_panic (expected = "StreamHandlerPool unbound")]
    fn panics_if_unbound() {
        let response_data = Vec::from (&b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 29\r\n\r\nUser-agent: *\nDisallow: /deny"[..]);
        let request = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:56789").unwrap (),
            last_data: false,
            data: PlainData::new (b"HEAD http://www.nyan.cat/ HTTP/1.1\r\n\r\n"),
            target_hostname: Some (String::from("target.hostname.com")),
            target_port: 1234,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new (&b"originator_public_key"[..]),
        };
        let cryptde = CryptDENull::new ();
        let package = ExpiredCoresPackage::new(
            test_utils::route_to_proxy_client(&cryptde.public_key(), &cryptde),
            PlainData::new(&serde_cbor::ser::to_vec (&request.clone()).unwrap ()[..])
        );
        let mut connect_parameters: Arc<Mutex<Vec<SocketAddr>>> = Arc::new (Mutex::new (vec! ()));
        let mut write_parameters: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new (Mutex::new (vec! ()));
        let mut set_read_timeout_parameters: Arc<Mutex<Vec<Option<Duration>>>> = Arc::new (Mutex::new (vec! ()));
        let mut shutdown_parameters: Arc<Mutex<Vec<Shutdown>>> = Arc::new (Mutex::new (vec! ()));
        let stream = TcpStreamWrapperMock::new ()
            .connect_result (Ok (()))
            .connect_parameters (&mut connect_parameters)
            .write_result (Ok (request.data.data.len ()))
            .write_parameters (&mut write_parameters)
            .set_read_timeout_result (Ok (()))
            .set_read_timeout_parameters (&mut set_read_timeout_parameters)
            .read_buffer (Vec::from (&response_data[0..40]))
            .read_result (Ok (40))
            .read_buffer (Vec::from (&response_data[40..]))
            .read_result (Ok (response_data.len () - 40))
            .shutdown_parameters (&mut shutdown_parameters)
            .shutdown_result (Ok (()));
        let tcp_stream_wrapper_factory = TcpStreamWrapperFactoryMock::new ()
            .tcp_stream_wrapper (stream);
        let system = System::new("panics_if_hopper_is_unbound");
        let mut subject = ProxyClient::new(Box::new (cryptde), dnss ());
        subject.tcp_stream_wrapper_factory = Box::new(tcp_stream_wrapper_factory);
        let subject_addr:SyncAddress<_> = subject.start();

        subject_addr.send(package);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();
    }

    #[test]
    fn data_from_hopper_is_relayed_to_stream_handler_pool () {
        let request = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:5678").unwrap (),
            last_data: false,
            data: PlainData::new (&b"inbound data"[..]),
            target_hostname: None,
            target_port: 0,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new (&b"originator"[..]),
        };
        let cryptde = CryptDENull::new();
        let package = ExpiredCoresPackage::new(
            test_utils::make_meaningless_route (),
            PlainData::new(&serde_cbor::ser::to_vec(&request.clone()).unwrap()[..])
        );
        let hopper = Recorder::new();

        let system = System::new("unparseable_request_results_in_log_and_no_response");
        let peer_actors = make_peer_actors_from(None, None, Some(hopper), None);
        let mut process_package_parameters = Arc::new (Mutex::new (vec! ()));
        let pool = Box::new (StreamHandlerPoolMock::new ()
                                 .process_package_parameters (&mut process_package_parameters));
        let pool_factory = StreamHandlerPoolFactoryMock::new ()
            .make_result (pool);
        let resolver = ResolverWrapperMock::new ()
            .lookup_ip_success (vec! (IpAddr::from_str ("4.3.2.1").unwrap ()));
        let resolver_factory = ResolverWrapperFactoryMock::new ()
            .new_result (Box::new (resolver));
        let mut subject = ProxyClient::new(Box::new(cryptde.clone()), dnss());
        subject.resolver_wrapper_factory = Box::new (resolver_factory);
        subject.stream_handler_pool_factory = Box::new (pool_factory);
        let subject_addr: SyncAddress<_> = subject.start();
        subject_addr.send(BindMessage{peer_actors});

        subject_addr.send(package);

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();
        let parameter = process_package_parameters.lock ().unwrap ().remove (0);
        assert_eq! (parameter, ExpiredCoresPackage {
            remaining_route: test_utils::make_meaningless_route(),
            payload: PlainData::new(&serde_cbor::ser::to_vec(&request.clone()).unwrap()[..]),
        });
    }
}
