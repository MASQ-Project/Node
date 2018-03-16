// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use std::thread;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use actix::Actor;
use actix::Context;
use actix::Handler;
use actix::Subscriber;
use actix::SyncAddress;
use resolver_wrapper::ResolverWrapperFactory;
use resolver_wrapper::ResolverWrapperFactoryReal;
use resolver_wrapper::ResolverWrapper;
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::config::NameServerConfig;
use trust_dns_resolver::config::Protocol;
use sub_lib::actor_messages::BindMessage;
use sub_lib::actor_messages::ExpiredCoresPackageMessage;
use sub_lib::actor_messages::IncipientCoresPackageMessage;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::PlainData;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::logger::Logger;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::proxy_client::ProxyClientSubs;
use sub_lib::tcp_wrappers::TcpStreamWrapper;
use sub_lib::tcp_wrappers::TcpStreamWrapperReal;
use stream_handler::StreamHandler;

pub struct ProxyClient {
    dns_servers: Vec<SocketAddr>,
    tcp_stream_wrapper_factory: Box<TcpStreamWrapperFactory>,
    resolver_wrapper_factory: Box<ResolverWrapperFactory>,
    resolver_wrapper: Option<Arc<Mutex<Box<ResolverWrapper>>>>,
    cryptde: Box<CryptDE>,
    to_hopper: Option<Box<Subscriber<IncipientCoresPackageMessage> + Send>>
}

impl Actor for ProxyClient {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for ProxyClient {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.to_hopper = Some(msg.peer_actors.hopper.from_hopper_client);
        let mut config = ResolverConfig::new ();
        for dns_server_ref in &self.dns_servers {
            config.add_name_server(NameServerConfig {
                socket_addr: *dns_server_ref,
                protocol: Protocol::Udp
            })
        }
        let opts = ResolverOpts::default ();
        self.resolver_wrapper = match self.resolver_wrapper_factory.new (config, opts) {
            Ok (resolver_wrapper_box) => Some (Arc::new (Mutex::new (resolver_wrapper_box))),
            Err (_) => unimplemented!()
        };
        ()
    }
}

impl Handler<ExpiredCoresPackageMessage> for ProxyClient {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackageMessage, _ctx: &mut Self::Context) -> Self::Result {
        let stream = self.tcp_stream_wrapper_factory.make ();
        ProxyClient::spawn_stream_thread(msg.pkg,
                                         self.to_hopper.as_ref().expect("Hopper Unbound for ProxyClient").clone(),
                                         self.resolver_wrapper.as_ref ().expect ("Unbound").clone (), stream);
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
            resolver_wrapper: None,
            cryptde,
            to_hopper: None,
        }
    }

    fn spawn_stream_thread(expired_cores_package: ExpiredCoresPackage, hopper: Box<Subscriber<IncipientCoresPackageMessage> + Send>,
                           resolver_arc: Arc<Mutex<Box<ResolverWrapper>>>, stream: Box<TcpStreamWrapper>) {
        thread::spawn (move || {
            let logger = Logger::new ("Proxy Client");
            logger.debug (format! ("Started thread"));
            match StreamHandler::new (expired_cores_package, hopper.clone (), resolver_arc.clone (), stream) {
                Some (mut handler) => handler.go (),
                None => ()
            };
            logger.debug (format! ("Stopping thread"));
        });
    }

    pub fn make_subs_from(addr: &SyncAddress<ProxyClient>) -> ProxyClientSubs {
        ProxyClientSubs {
            bind: addr.subscriber::<BindMessage>(),
            from_hopper: addr.subscriber::<ExpiredCoresPackageMessage>(),
        }
    }
}

trait TcpStreamWrapperFactory {
    fn make (&self) -> Box<TcpStreamWrapper>;
}

struct TcpStreamWrapperFactoryReal {}

impl TcpStreamWrapperFactory for TcpStreamWrapperFactoryReal {
    fn make (&self) -> Box<TcpStreamWrapper> {
        Box::new (TcpStreamWrapperReal::new ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::io::Write;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::net::Shutdown;
    use std::time::Duration;
    use std::time::Instant;
    use std::sync::MutexGuard;
    use std::str::FromStr;
    use std::ops::DerefMut;
    use std::cell::RefCell;
    use std::fmt::Debug;
    use actix::System;
    use actix::Arbiter;
    use actix::msgs;
    use serde_cbor;
    use sub_lib::route::Route;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::logger::LoggerInitializerWrapper;
    use sub_lib::test_utils::LoggerInitializerWrapperMock;
    use sub_lib::test_utils::TestLogHandler;
    use sub_lib::test_utils::make_peer_actors;
    use sub_lib::test_utils::make_peer_actors_from;
    use sub_lib::test_utils::Recorder;
    use resolver_wrapper::tests::ResolverWrapperFactoryMock;
    use resolver_wrapper::tests::ResolverWrapperMock;
    use stream_handler::RESPONSE_FINISHED_TIMEOUT_MS;
    use stream_handler::SERVER_PROBLEM_RESPONSE;

    fn dnss () -> Vec<SocketAddr> {
        vec! (SocketAddr::from_str ("8.8.8.8:53").unwrap ())
    }

    fn target_ip () -> IpAddr {
        IpAddr::from_str ("1.2.3.4").unwrap ()
    }

    struct TcpStreamWrapperFactoryMock {
        tcp_stream_wrappers: RefCell<Vec<Box<TcpStreamWrapper>>>
    }

    impl TcpStreamWrapperFactory for TcpStreamWrapperFactoryMock {
        fn make(&self) -> Box<TcpStreamWrapper> {
            self.tcp_stream_wrappers.borrow_mut ().remove (0)
        }
    }

    impl TcpStreamWrapperFactoryMock {
        pub fn new () -> TcpStreamWrapperFactoryMock {
            TcpStreamWrapperFactoryMock {tcp_stream_wrappers: RefCell::new (Vec::new ())}
        }

        pub fn tcp_stream_wrapper (self, tcp_stream_wrapper: Box<TcpStreamWrapper>) -> TcpStreamWrapperFactoryMock {
            self.tcp_stream_wrappers.borrow_mut().push (tcp_stream_wrapper);
            self
        }
    }

    struct TcpStreamWrapperMock {
        connect_result: Option<io::Result<()>>,
        connect_parameter: Arc<Mutex<Option<SocketAddr>>>,
        write_result: Option<io::Result<usize>>,
        write_parameter: Arc<Mutex<Option<Vec<u8>>>>,
        read_buffers: Vec<Vec<u8>>,
        read_results: Vec<io::Result<usize>>,
        shutdown_result: RefCell<Option<io::Result<()>>>,
        shutdown_parameter: RefCell<Arc<Mutex<Option<Shutdown>>>>,
        set_read_timeout_result: RefCell<Option<io::Result<()>>>,
        set_read_timeout_parameter: RefCell<Arc<Mutex<Option<Option<Duration>>>>>
    }

    fn store_parameter_and_return_result<P, R> (parameter: P, parameter_arc: &Arc<Mutex<Option<P>>>,
                                                result: &mut Option<R>) -> R where P: Debug {
        let mut parameter_guard = parameter_arc.lock ().unwrap ();
        let parameter_ref = parameter_guard.deref_mut ();
        *parameter_ref = Some (parameter);
        result.take ().unwrap ()
    }

    fn store_parameter_and_return_result_immutable<P, R> (parameter: P, parameter_refcell: &RefCell<Arc<Mutex<Option<P>>>>,
                                                          result: &RefCell<Option<R>>) -> R {
        let parameter_arc = parameter_refcell.borrow_mut();
        let mut parameter_guard = parameter_arc.as_ref ().lock ().unwrap ();
        let parameter_ref = parameter_guard.deref_mut ();
        *parameter_ref = Some (parameter);
        result.borrow_mut ().take ().unwrap ()
    }

    impl TcpStreamWrapper for TcpStreamWrapperMock {
        fn connect(&mut self, addr: SocketAddr) -> io::Result<()> {
            store_parameter_and_return_result (addr, &self.connect_parameter, &mut self.connect_result)
        }

        fn shutdown(&self, how: Shutdown) -> io::Result<()> {
            store_parameter_and_return_result_immutable (how, &self.shutdown_parameter, &self.shutdown_result)
        }

        fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            store_parameter_and_return_result_immutable (dur, &self.set_read_timeout_parameter, &self.set_read_timeout_result)
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> { unimplemented!() }
        fn local_addr(&self) -> io::Result<SocketAddr> { unimplemented!() }
        fn set_write_timeout(&self, _dur: Option<Duration>) -> io::Result<()> { unimplemented!() }
        fn read_timeout(&self) -> io::Result<Option<Duration>> { unimplemented!() }
        fn write_timeout(&self) -> io::Result<Option<Duration>> { unimplemented!() }
        fn peek(&self, _buf: &mut [u8]) -> io::Result<usize> { unimplemented!() }
        fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> { unimplemented!() }
        fn nodelay(&self) -> io::Result<bool> { unimplemented!() }
        fn set_ttl(&self, _ttl: u32) -> io::Result<()> { unimplemented!() }
        fn ttl(&self) -> io::Result<u32> { unimplemented!() }
        fn take_error(&self) -> io::Result<Option<io::Error>> { unimplemented!() }
        fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> { unimplemented!() }
        fn try_clone(&self) -> io::Result<Box<TcpStreamWrapper>> { unimplemented!() }
    }

    impl Read for TcpStreamWrapperMock {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.read_buffers.len () > 0 {
                let chunk = self.read_buffers.remove(0);
                for index in 0..chunk.len() { buf[index] = chunk[index] }
            }
            self.read_results.remove (0)
        }
    }
    impl Write for TcpStreamWrapperMock {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            store_parameter_and_return_result (Vec::from (buf), &self.write_parameter, &mut self.write_result)
        }

        fn flush(&mut self) -> io::Result<()> {
            unimplemented!()
        }
    }

    impl TcpStreamWrapperMock {
        pub fn new () -> TcpStreamWrapperMock {
            TcpStreamWrapperMock {
                connect_result: None,
                connect_parameter: Arc::new (Mutex::new (None)),
                read_buffers: vec! (),
                read_results: vec! (),
                write_result: None,
                write_parameter: Arc::new (Mutex::new (None)),
                shutdown_result: RefCell::new (None),
                shutdown_parameter: RefCell::new (Arc::new (Mutex::new (None))),
                set_read_timeout_result: RefCell::new (None),
                set_read_timeout_parameter: RefCell::new (Arc::new (Mutex::new (None)))
            }
        }

        pub fn connect_result (mut self, result: io::Result<()>) -> TcpStreamWrapperMock {
            self.connect_result = Some (result);
            self
        }

        pub fn connect_parameter (self, parameter: &mut Arc<Mutex<Option<SocketAddr>>>) -> TcpStreamWrapperMock {
            *parameter = self.connect_parameter.clone ();
            self
        }

        pub fn write_result (mut self, result: io::Result<usize>) -> TcpStreamWrapperMock {
            self.write_result = Some (result);
            self
        }

        pub fn write_parameter (self, parameter: &mut Arc<Mutex<Option<Vec<u8>>>>) -> TcpStreamWrapperMock {
            *parameter = self.write_parameter.clone ();
            self
        }

        pub fn read_buffers (mut self, buffers: Vec<Vec<u8>>) -> TcpStreamWrapperMock {
            self.read_buffers = buffers;
            self
        }

        pub fn read_results (mut self, results: Vec<io::Result<usize>>) -> TcpStreamWrapperMock {
            self.read_results = results;
            self
        }

        pub fn shutdown_result (mut self, result: io::Result<()>) -> TcpStreamWrapperMock {
            self.shutdown_result = RefCell::new (Some (result));
            self
        }

        pub fn shutdown_parameter (self, parameter: &mut Arc<Mutex<Option<Shutdown>>>) -> TcpStreamWrapperMock {
            *parameter = self.shutdown_parameter.borrow_mut ().clone ();
            self
        }

        pub fn set_read_timeout_result (mut self, result: io::Result<()>) -> TcpStreamWrapperMock {
            self.set_read_timeout_result = RefCell::new (Some (result));
            self
        }

        pub fn set_read_timeout_parameter (self, parameter: &mut Arc<Mutex<Option<Option<Duration>>>>) -> TcpStreamWrapperMock {
            *parameter = self.set_read_timeout_parameter.borrow_mut ().clone ();
            self
        }
    }

    #[test]
    #[should_panic (expected = "Proxy Client requires at least one DNS server IP address after the --dns_servers parameter")]
    fn at_least_one_dns_server_must_be_provided () {
        ProxyClient::new (Box::new (CryptDENull::new ()), vec! ());
    }

    #[test]
    fn bind_initializes_resolver_wrapper_properly () {
        let system = System::new("bind_initializes_resolver_wrapper_properly");
        let resolver_wrapper = ResolverWrapperMock::new ();
        let mut new_parameters: Arc<Mutex<Vec<(ResolverConfig, ResolverOpts)>>> = Arc::new (Mutex::new (vec! ()));
        let resolver_wrapper_factory = ResolverWrapperFactoryMock::new ()
            .new_result(Ok (Box::new (resolver_wrapper)))
            .new_parameters (&mut new_parameters);
        let peer_actors = make_peer_actors();
        let mut subject = ProxyClient::new (Box::new (CryptDENull::new ()), vec! (
            SocketAddr::from_str ("4.3.2.1:4321").unwrap (),
            SocketAddr::from_str ("5.4.3.2:5432").unwrap ()
        ));
        subject.resolver_wrapper_factory = Box::new (resolver_wrapper_factory);
        let subject_addr: SyncAddress<_> = subject.start();

        subject_addr.send(BindMessage { peer_actors });

        Arbiter::system().send(msgs::SystemExit(0));
        system.run();

        let mut parameters_guard = new_parameters.lock ().unwrap ();
        let (config, opts) = parameters_guard.remove (0);
        assert_eq! (config.domain (), None);
        assert_eq! (config.search (), &[]);
        assert_eq! (config.name_servers (), &[
            NameServerConfig {socket_addr: SocketAddr::from_str ("4.3.2.1:4321").unwrap (), protocol: Protocol::Udp},
            NameServerConfig {socket_addr: SocketAddr::from_str ("5.4.3.2:5432").unwrap (), protocol: Protocol::Udp},
        ]);
        assert_eq! (opts, ResolverOpts::default ());
        assert_eq! (parameters_guard.is_empty (), true);
    }

    #[test]
    fn successful_round_trip_without_chunks () {
        let mut response_data = Vec::from (&b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 29\r\n\r\nUser-agent: *\nDisallow: /deny"[..]);
        let framed_response_data = response_data.clone ();
        for c in b"garbage" {response_data.insert (0, *c)}
        response_data.extend (b"HTTP/1.1 200 Another");
        let request = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:56789").unwrap (),
            data: PlainData::new (b"HEAD http://www.nyan.cat/ HTTP/1.1\r\n\r\n"),
            target_hostname: String::from("target.hostname.com"),
            target_port: 1234,
            originator_public_key: Key::new (&b"originator_public_key"[..]),
        };
        let cryptde = CryptDENull::new ();
        let thread_cryptde = cryptde.clone();
        let package = ExpiredCoresPackage::new(
            Route::rel2_to_proxy_client(&cryptde.public_key(), &cryptde).unwrap(),
            PlainData::new(&serde_cbor::ser::to_vec (&request.clone()).unwrap ()[..])
        );
        let mut connect_parameter: Arc<Mutex<Option<SocketAddr>>> = Arc::new (Mutex::new (None));
        let mut write_parameter: Arc<Mutex<Option<Vec<u8>>>> = Arc::new (Mutex::new (None));
        let mut set_read_timeout_parameter: Arc<Mutex<Option<Option<Duration>>>> = Arc::new (Mutex::new (None));
        let mut shutdown_parameter: Arc<Mutex<Option<Shutdown>>> = Arc::new (Mutex::new (None));
        let stream_box = Box::new (TcpStreamWrapperMock::new ()
            .connect_result (Ok (()))
            .connect_parameter (&mut connect_parameter)
            .write_result (Ok (request.data.data.len ()))
            .write_parameter (&mut write_parameter)
            .set_read_timeout_result (Ok (()))
            .set_read_timeout_parameter (&mut set_read_timeout_parameter)
            .read_buffers (vec! (
                Vec::from (&response_data[0..40]),
                Vec::from (&response_data[40..])
            ))
            .read_results (vec! (Ok (40), Ok (response_data.len () - 40)))
            .shutdown_parameter (&mut shutdown_parameter)
            .shutdown_result (Ok (())));
        let tcp_stream_wrapper_factory = TcpStreamWrapperFactoryMock::new ()
            .tcp_stream_wrapper (stream_box);
        let mut lookup_ip_parameter_arc: Arc<Mutex<Vec<String>>> = Arc::new (Mutex::new (vec! ()));
        let resolver_wrapper = ResolverWrapperMock::new ()
            .lookup_ip_result (Ok (vec! (target_ip ())))
            .lookup_ip_parameters (&mut lookup_ip_parameter_arc);
        let resolver_wrapper_factory = ResolverWrapperFactoryMock::new ()
            .new_result(Ok (Box::new (resolver_wrapper)));
        let hopper = Recorder::new ();
        let hopper_recording = hopper.get_recording();
        let awaiter = hopper.get_awaiter();
        thread::spawn(move || {
            let system = System::new("successful_round_trip");
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            let mut subject = ProxyClient::new(Box::new (thread_cryptde), dnss ());
            subject.tcp_stream_wrapper_factory = Box::new(tcp_stream_wrapper_factory);
            subject.resolver_wrapper_factory = Box::new (resolver_wrapper_factory);
            let subject_addr:SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage{peer_actors});

            subject_addr.send(ExpiredCoresPackageMessage{pkg: package});

            system.run();
        });

        let shutdown_parameter_guard = verify_arc_mutex_option(&shutdown_parameter, 1000);
        let connect_parameter_guard = connect_parameter.lock ().unwrap ();
        assert_eq! (*connect_parameter_guard.as_ref ().unwrap (), SocketAddr::new (target_ip (), 1234));;
        let write_parameter_guard = write_parameter.lock().unwrap ();
        assert_eq! (*write_parameter_guard.as_ref ().unwrap (), request.data.data);
        let set_read_timeout_parameter_guard = set_read_timeout_parameter.lock ().unwrap ();
        assert_eq! (*set_read_timeout_parameter_guard.as_ref ().unwrap (), Some (Duration::from_millis(RESPONSE_FINISHED_TIMEOUT_MS)));
        assert_eq! (*shutdown_parameter_guard.as_ref ().unwrap (), Shutdown::Both);
        let lookup_ip_parameter_guard = lookup_ip_parameter_arc.lock ().unwrap ();
        assert_eq! (*lookup_ip_parameter_guard.first ().unwrap (), String::from ("target.hostname.com."));

        awaiter.await_message_count(1);
        let recording = hopper_recording.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackageMessage>(0);
        let expected_client_response_payload = ClientResponsePayload {stream_key: request.stream_key,
            last_response: true, data: PlainData::new (&framed_response_data[..])};
        let serialized_client_response_payload = serde_cbor::ser::to_vec (&expected_client_response_payload).unwrap ();
        assert_eq! (record.pkg.route, Route::rel2_from_proxy_client(&cryptde.public_key (), &cryptde).unwrap ());
        assert_eq! (record.pkg.payload, PlainData::new (&serialized_client_response_payload[..]));
        assert_eq! (record.pkg.payload_destination_key, request.originator_public_key);
    }

    #[test]
    fn successful_round_trip_with_chunks () {
        let response_data = Vec::from (&b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\nE\r\nUser-agent: *\n\r\nF\r\nDisallow: /deny\r\n0\r\n\r\n"[..]);
        let request = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:56789").unwrap (),
            data: PlainData::new (b"HEAD http://www.nyan.cat/ HTTP/1.1\r\n\r\n"),
            target_hostname: String::from("target.hostname.com"),
            target_port: 1234,
            originator_public_key: Key::new (&b"originator_public_key"[..]),
        };
        let cryptde = CryptDENull::new ();
        let thread_cryptde = cryptde.clone();
        let package = ExpiredCoresPackage::new(
            Route::rel2_to_proxy_client(&cryptde.public_key(), &cryptde).unwrap(),
            PlainData::new(&serde_cbor::ser::to_vec (&request.clone()).unwrap ()[..])
        );
        let mut connect_parameter: Arc<Mutex<Option<SocketAddr>>> = Arc::new (Mutex::new (None));
        let mut write_parameter: Arc<Mutex<Option<Vec<u8>>>> = Arc::new (Mutex::new (None));
        let mut set_read_timeout_parameter: Arc<Mutex<Option<Option<Duration>>>> = Arc::new (Mutex::new (None));
        let mut shutdown_parameter: Arc<Mutex<Option<Shutdown>>> = Arc::new (Mutex::new (None));
        let stream_box = Box::new (TcpStreamWrapperMock::new ()
            .connect_result (Ok (()))
            .connect_parameter (&mut connect_parameter)
            .write_result (Ok (request.data.data.len ()))
            .write_parameter (&mut write_parameter)
            .set_read_timeout_result (Ok (()))
            .set_read_timeout_parameter (&mut set_read_timeout_parameter)
            .read_buffers (vec! (
                Vec::from (&response_data[0..80]),
                Vec::from (&response_data[80..])
            ))
            .read_results (vec! (Ok (80), Ok (response_data.len () - 80)))
            .shutdown_parameter (&mut shutdown_parameter)
            .shutdown_result (Ok (())));
        let tcp_stream_wrapper_factory = TcpStreamWrapperFactoryMock::new ()
            .tcp_stream_wrapper (stream_box);
        let mut lookup_ip_parameter_arc: Arc<Mutex<Vec<String>>> = Arc::new (Mutex::new (vec! ()));
        let resolver_wrapper = ResolverWrapperMock::new ()
            .lookup_ip_result (Ok (vec! (target_ip ())))
            .lookup_ip_parameters (&mut lookup_ip_parameter_arc);
        let resolver_wrapper_factory = ResolverWrapperFactoryMock::new ()
            .new_result(Ok (Box::new (resolver_wrapper)));
        let hopper = Recorder::new ();
        let hopper_recording = hopper.get_recording();
        let awaiter = hopper.get_awaiter();
        thread::spawn(move || {
            let system = System::new("successful_round_trip");
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            let mut subject = ProxyClient::new(Box::new (thread_cryptde), dnss ());
            subject.tcp_stream_wrapper_factory = Box::new(tcp_stream_wrapper_factory);
            subject.resolver_wrapper_factory = Box::new (resolver_wrapper_factory);
            let subject_addr:SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage{peer_actors});

            subject_addr.send(ExpiredCoresPackageMessage{pkg: package});

            system.run();
        });

        let shutdown_parameter_guard = verify_arc_mutex_option(&shutdown_parameter, 1000);
        assert_eq! (*shutdown_parameter_guard.as_ref ().unwrap (), Shutdown::Both);
        let expected_client_response_payloads = vec!(
            ClientResponsePayload {
                stream_key: request.stream_key,
                last_response: false,
                data: PlainData::new(&b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"[..]),
            },
            ClientResponsePayload {
                stream_key: request.stream_key,
                last_response: false,
                data: PlainData::new(&b"E\r\nUser-agent: *\n\r\n"[..]),
            },
            ClientResponsePayload {
                stream_key: request.stream_key,
                last_response: false,
                data: PlainData::new(&b"F\r\nDisallow: /deny\r\n"[..]),
            },
            ClientResponsePayload {
                stream_key: request.stream_key,
                last_response: true,
                data: PlainData::new(&b"0\r\n\r\n"[..]),
            },
        );
        let expected_packages: Vec<IncipientCoresPackage> = expected_client_response_payloads.iter ().map (|p| {
            IncipientCoresPackage::new (
                Route::rel2_from_proxy_client(&cryptde.public_key (), &cryptde).unwrap (),
                p.clone (),
                &request.originator_public_key,
            )
        }).collect ();

        awaiter.await_message_count(4); // probably unnecessary
        let recording = hopper_recording.lock().unwrap();
        let actual_packages: Vec<&IncipientCoresPackage> = vec! (0, 1, 2, 3).iter ().map (|index| {
            let record = recording.get_record::<IncipientCoresPackageMessage> (*index);
            &record.pkg
        }).collect ();

        assert_eq! (*actual_packages[0], expected_packages[0]);
        assert_eq! (*actual_packages[1], expected_packages[1]);
        assert_eq! (*actual_packages[2], expected_packages[2]);
        assert_eq! (*actual_packages[3], expected_packages[3]);
    }

    #[test]
    fn unparseable_request_results_in_log_and_no_response () {
        LoggerInitializerWrapperMock::new().init();
        let request = String::from("not parseable as ClientRequestPayload");
        let cryptde = CryptDENull::new();
        let package = ExpiredCoresPackage::new(
            Route::rel2_to_proxy_client(&cryptde.public_key(), &cryptde).unwrap(),
            PlainData::new(&serde_cbor::ser::to_vec(&request.clone()).unwrap()[..])
        );
        let hopper = Recorder::new();
        thread::spawn(move || {
            let system = System::new("unparseable_request_results_in_log_and_no_response");
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            let subject = ProxyClient::new(Box::new(cryptde.clone()), dnss());
            let subject_addr: SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage{peer_actors});

            subject_addr.send(ExpiredCoresPackageMessage{pkg:package});

            system.run();
        });

        TestLogHandler::new ().await_log_matching ("ThreadId\\(\\d+\\): ERROR: Proxy Client: Unparseable request discarded \\(invalid type: string \"not parseable as ClientRequestPayload\", expected struct ClientRequestPayload\\):",
                                                   1000);
    }

    #[test]
    fn dns_error_results_in_503 () {
        LoggerInitializerWrapperMock::new ().init ();
        let request = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:56789").unwrap (),
            data: PlainData::new (b"HEAD http://www.nyan.cat/ HTTP/1.1\r\n\r\n"),
            target_hostname: String::from("target.hostname.com"),
            target_port: 1234,
            originator_public_key: Key::new (&b"originator_public_key"[..]),
        };
        let cryptde = CryptDENull::new ();
        let thread_cryptde = cryptde.clone();
        let package = ExpiredCoresPackage::new(
            Route::rel2_to_proxy_client(&cryptde.public_key(), &cryptde).unwrap(),
            PlainData::new(&serde_cbor::ser::to_vec (&request.clone()).unwrap ()[..])
        );
        let resolver_wrapper = ResolverWrapperMock::new ()
            .lookup_ip_result (Ok (vec! ()));
        let resolver_wrapper_factory = ResolverWrapperFactoryMock::new ()
            .new_result(Ok (Box::new (resolver_wrapper)));
        let hopper = Recorder::new ();
        let hopper_recording = hopper.get_recording();
        let awaiter = hopper.get_awaiter();
        thread::spawn(move || {
            let system = System::new("dns_error_results_in_503");
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            let mut subject = ProxyClient::new(Box::new (thread_cryptde), dnss ());
            subject.resolver_wrapper_factory = Box::new (resolver_wrapper_factory);
            let subject_addr: SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage{peer_actors});

            subject_addr.send(ExpiredCoresPackageMessage{pkg:package});

            system.run();
        });

        TestLogHandler::new ().await_log_matching ("ThreadId\\(\\d+\\): ERROR: Proxy Client: DNS search for hostname 'target.hostname.com.' produced no results", 1000);
        awaiter.await_message_count(1);
        let recording = hopper_recording.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackageMessage>(0);
        let expected_client_response_payload = ClientResponsePayload {stream_key: request.stream_key,
            last_response: true, data: PlainData::new (SERVER_PROBLEM_RESPONSE)};
        let serialized_client_response_payload = serde_cbor::ser::to_vec (&expected_client_response_payload).unwrap ();
        assert_eq! (record.pkg.route, Route::rel2_from_proxy_client(&cryptde.public_key (), &cryptde).unwrap ());
        assert_eq! (record.pkg.payload, PlainData::new (&serialized_client_response_payload[..]));
        assert_eq! (record.pkg.payload_destination_key, request.originator_public_key);
    }

    #[test]
    fn connect_error_results_in_log_and_503 () {
        verify_error_results (
            TcpStreamWrapperMock::new ()
                .connect_result (Err (Error::from (ErrorKind::ConnectionRefused))),
            format! ("ThreadId\\(\\d+\\): ERROR: Proxy Client: Could not connect to server at {} for HEAD http://www.nyan.cat/: connection refused",
                     SocketAddr::new (target_ip (), 1234)),
            false
        );
    }

    #[test]
    fn write_error_results_in_log_and_503 () {
        verify_error_results (
            TcpStreamWrapperMock::new ()
                .connect_result (Ok (()))
                .write_result (Err (Error::from (ErrorKind::ConnectionAborted))),
            format! ("ThreadId\\(\\d+\\): ERROR: Proxy Client: Could not write to server at {} for HEAD http://www.nyan.cat/: connection aborted",
                     SocketAddr::new (target_ip (), 1234)),
            true
        );
    }

    #[test]
    fn set_read_timeout_error_results_in_log_and_503 () {
        let request = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:56789").unwrap (),
            data: PlainData::new (b"HEAD http://www.nyan.cat/ HTTP/1.1\r\n\r\n"),
            target_hostname: String::from("target.hostname.com"),
            target_port: 1234,
            originator_public_key: Key::new (&b"originator_public_key"[..]),
        };
        verify_error_results (
            TcpStreamWrapperMock::new ()
                .connect_result (Ok (()))
                .write_result (Ok (request.data.data.len ()))
                .set_read_timeout_result (Err (Error::from (ErrorKind::InvalidInput))),
            format! ("ThreadId\\(\\d+\\): ERROR: Proxy Client: Could not set read timeout on stream from {} for HEAD http://www.nyan.cat/: invalid input",
                     SocketAddr::new (target_ip (), 1234)),
            true
        );
    }

    #[test]
    fn read_error_that_is_not_timeout_results_in_log_and_503 () {
        let request = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:56789").unwrap (),
            data: PlainData::new (b"HEAD http://www.nyan.cat/ HTTP/1.1\r\n\r\n"),
            target_hostname: String::from("target.hostname.com"),
            target_port: 1234,
            originator_public_key: Key::new (&b"originator_public_key"[..]),
        };
        verify_error_results (
            TcpStreamWrapperMock::new ()
                .connect_result (Ok (()))
                .write_result (Ok (request.data.data.len ()))
                .set_read_timeout_result (Ok (()))
                .read_results (vec! (Err (Error::from (ErrorKind::AddrInUse)))),
            format! ("ERROR: Proxy Client: Could not read from server at {} for HEAD http://www.nyan.cat/: address in use",
                     SocketAddr::new (target_ip (), 1234)),
            true
        );
    }

    #[test]
    fn read_error_that_is_timeout_results_in_log_and_503 () {
        let request = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:56789").unwrap (),
            data: PlainData::new (b"HEAD http://www.nyan.cat/ HTTP/1.1\r\n\r\n"),
            target_hostname: String::from("target.hostname.com"),
            target_port: 1234,
            originator_public_key: Key::new (&b"originator_public_key"[..]),
        };
        verify_error_results (
            TcpStreamWrapperMock::new ()
                .connect_result (Ok (()))
                .write_result (Ok (request.data.data.len ()))
                .set_read_timeout_result (Ok (()))
                .read_results (vec! (Err (Error::from (timeout_error_kind())))),
            format! ("ERROR: Proxy Client: Could not read from server at {} for HEAD http://www.nyan.cat/: {}",
                     SocketAddr::new (target_ip (), 1234), Error::from (timeout_error_kind ())),
            true
        );
    }

    #[test]
    fn shutdown_error_is_logged () {
        LoggerInitializerWrapperMock::new ().init ();
        let request = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:56789").unwrap (),
            data: PlainData::new (b"HEAD http://www.nyan.cat/ HTTP/1.1\r\n\r\n"),
            target_hostname: String::from("target.hostname.com"),
            target_port: 1234,
            originator_public_key: Key::new (&b"originator_public_key"[..]),
        };
        let response_data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 29\r\n\r\nUser-agent: *\nDisallow: /deny";
        let cryptde = CryptDENull::new ();
        let thread_cryptde = cryptde.clone();
        let package = ExpiredCoresPackage::new(
            Route::rel2_to_proxy_client(&cryptde.public_key(), &cryptde).unwrap(),
            PlainData::new(&serde_cbor::ser::to_vec (&request.clone()).unwrap ()[..])
        );
        let stream = Box::new (TcpStreamWrapperMock::new ()
            .connect_result (Ok (()))
            .write_result (Ok (request.data.data.len ()))
            .set_read_timeout_result (Ok (()))
            .read_buffers (vec! (
                Vec::from (&response_data[..]),
                Vec::new ()
            ))
            .read_results (vec! (Ok (response_data.len ()), Ok (0)))
            .shutdown_result (Err (Error::from (ErrorKind::BrokenPipe))));
        let tcp_stream_wrapper_factory = TcpStreamWrapperFactoryMock::new ()
            .tcp_stream_wrapper (stream);
        let resolver_wrapper = ResolverWrapperMock::new ()
            .lookup_ip_result (Ok (vec! (target_ip ())));
        let resolver_wrapper_factory = ResolverWrapperFactoryMock::new ()
            .new_result(Ok (Box::new (resolver_wrapper)));

        let hopper = Recorder::new ();
        let hopper_recording = hopper.get_recording();
        let awaiter = hopper.get_awaiter();
        thread::spawn(move || {
            let system = System::new("dns_error_results_in_503");
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            let mut subject = ProxyClient::new(Box::new (thread_cryptde), vec! (SocketAddr::from_str ("2.3.4.5:6789").unwrap ()));
            subject.tcp_stream_wrapper_factory = Box::new(tcp_stream_wrapper_factory);
            subject.resolver_wrapper_factory = Box::new (resolver_wrapper_factory);
            let subject_addr: SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage{peer_actors});

            subject_addr.send(ExpiredCoresPackageMessage{pkg:package});

            system.run();
        });

        TestLogHandler::new ().await_log_matching ("ThreadId\\(\\d+\\): WARN: Proxy Client: Stream shutdown failure for HEAD http://www.nyan.cat/: broken pipe", 1000);
        awaiter.await_message_count(1);
        let recording = hopper_recording.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackageMessage>(0);
        let expected_client_response_payload = ClientResponsePayload {stream_key: request.stream_key,
            last_response: true, data: PlainData::new (response_data)};
        let serialized_client_response_payload = serde_cbor::ser::to_vec (&expected_client_response_payload).unwrap ();
        assert_eq! (record.pkg.route, Route::rel2_from_proxy_client(&cryptde.public_key (), &cryptde).unwrap ());
        assert_eq! (record.pkg.payload, PlainData::new (&serialized_client_response_payload[..]));
        assert_eq! (record.pkg.payload_destination_key, Key::new (&b"originator_public_key"[..]));
    }

    fn verify_error_results (stream: TcpStreamWrapperMock, expected_log_regex: String, expect_shutdown: bool) {
        LoggerInitializerWrapperMock::new ().init ();
        let request = ClientRequestPayload {
            stream_key: SocketAddr::from_str ("1.2.3.4:56789").unwrap (),
            data: PlainData::new (b"HEAD http://www.nyan.cat/ HTTP/1.1\r\n\r\n"),
            target_hostname: String::new(),
            target_port: 1234,
            originator_public_key: Key::new (&[]),
        };
        let cryptde = CryptDENull::new ();
        let thread_cryptde = cryptde.clone();
        let package = ExpiredCoresPackage::new(
            Route::rel2_to_proxy_client(&cryptde.public_key(), &cryptde).unwrap(),
            PlainData::new(&serde_cbor::ser::to_vec (&request.clone()).unwrap ()[..])
        );
        let mut shutdown_parameter: Arc<Mutex<Option<Shutdown>>> = Arc::new (Mutex::new (None));
        let stream_box = Box::new (stream
            .shutdown_parameter (&mut shutdown_parameter)
            .shutdown_result (Ok (()))
        );
        let tcp_stream_wrapper_factory = TcpStreamWrapperFactoryMock::new ()
            .tcp_stream_wrapper (stream_box);
        let mut lookup_ip_parameter_arc: Arc<Mutex<Vec<String>>> = Arc::new (Mutex::new (vec! ()));
        let resolver_wrapper = ResolverWrapperMock::new ()
            .lookup_ip_result (Ok (vec! (target_ip ())))
            .lookup_ip_parameters (&mut lookup_ip_parameter_arc);
        let resolver_wrapper_factory = ResolverWrapperFactoryMock::new ()
            .new_result(Ok (Box::new (resolver_wrapper)));

        let hopper = Recorder::new ();
        let hopper_recording = hopper.get_recording();
        let awaiter = hopper.get_awaiter();
        thread::spawn(move || {
            let system = System::new("dns_error_results_in_503");
            let peer_actors = make_peer_actors_from(None, None, Some(hopper), None, None);
            let mut subject = ProxyClient::new(Box::new (thread_cryptde), dnss ());
            subject.tcp_stream_wrapper_factory = Box::new(tcp_stream_wrapper_factory);
            subject.resolver_wrapper_factory = Box::new (resolver_wrapper_factory);
            let subject_addr: SyncAddress<_> = subject.start();
            subject_addr.send(BindMessage{peer_actors});

            subject_addr.send(ExpiredCoresPackageMessage{pkg:package});

            system.run();
        });

        TestLogHandler::new ().await_log_matching (&expected_log_regex[..], 1000);
        if expect_shutdown {
            let shutdown_parameter_guard = shutdown_parameter.lock().unwrap();
            assert_eq!(*shutdown_parameter_guard.as_ref().unwrap(), Shutdown::Both);
        }
        awaiter.await_message_count(1);
        let recording = hopper_recording.lock().unwrap();
        let record = recording.get_record::<IncipientCoresPackageMessage>(0);
        let expected_client_response_payload = ClientResponsePayload {stream_key: request.stream_key,
            last_response: true, data: PlainData::new (SERVER_PROBLEM_RESPONSE)};
        let serialized_client_response_payload = serde_cbor::ser::to_vec (&expected_client_response_payload).unwrap ();
        assert_eq! (record.pkg.route, Route::rel2_from_proxy_client(&cryptde.public_key (), &cryptde).unwrap ());
        assert_eq! (record.pkg.payload, PlainData::new (&serialized_client_response_payload[..]));
        assert_eq! (record.pkg.payload_destination_key, request.originator_public_key);
    }

    fn verify_arc_mutex_option<'a, T> (arc_mutex_option: &'a Arc<Mutex<Option<T>>>, millis: u64) -> MutexGuard<'a, Option<T>> {
        match wait_for_arc_mutex_option(arc_mutex_option, millis) {
            Some(guard) => guard,
            None => panic!("Waited for more than {} milliseconds", millis)
        }
    }

    fn wait_for_arc_mutex_option<'a, T> (arc_mutex_option: &'a Arc<Mutex<Option<T>>>, millis: u64) -> Option<MutexGuard<'a, Option<T>>> {
        let start = Instant::now ();
        while Instant::now ().duration_since (start).le (&Duration::from_millis (millis)) {
            {
                let guard = arc_mutex_option.lock ().unwrap ();
                if guard.is_some() {return Some (guard)}
            }
            thread::sleep (Duration::from_millis (10))
        }
        return None
    }

    #[cfg (unix)]
    fn timeout_error_kind () -> ErrorKind {ErrorKind::WouldBlock}

    #[cfg (windows)]
    fn timeout_error_kind () -> ErrorKind {ErrorKind::TimedOut}
}
