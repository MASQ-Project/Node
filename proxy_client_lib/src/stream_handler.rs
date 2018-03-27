// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::Shutdown;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use actix::Subscriber;
use sub_lib::cryptde::PlainData;
use sub_lib::framer::Framer;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::http_packet_framer;
use sub_lib::http_packet_framer::HttpPacketFramer;
use sub_lib::http_response_start_finder::HttpResponseStartFinder;
use sub_lib::logger::Logger;
use sub_lib::proxy_client::ClientResponsePayload;
use sub_lib::proxy_server::ClientRequestPayload;
use sub_lib::tcp_wrappers::TcpStreamWrapper;
use sub_lib::utils::to_string;
use resolver_wrapper::ResolverWrapper;

pub const RESPONSE_FINISHED_TIMEOUT_MS: u64 = 120000;
pub const SERVER_PROBLEM_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 26\r\n\r\nSubstratum Network problem";

pub struct StreamHandler {
    expired_cores_package: ExpiredCoresPackage,
    client_request_payload: ClientRequestPayload,
    hopper: Box<Subscriber<IncipientCoresPackage> + Send>,
    resolver_arc: Arc<Mutex<Box<ResolverWrapper>>>,
    stream: Box<TcpStreamWrapper>,
    logger: Logger
}

impl StreamHandler {

    pub fn new (expired_cores_package: ExpiredCoresPackage, hopper: Box<Subscriber<IncipientCoresPackage> + Send>,
            resolver_arc: Arc<Mutex<Box<ResolverWrapper>>>, stream: Box<TcpStreamWrapper>) -> Option<StreamHandler> {
        let logger = Logger::new ("Proxy Client");
        let client_request_payload: ClientRequestPayload = match expired_cores_package.payload () {
            Ok(p) => p,
            Err(e) => {
                logger.error (format! ("Unparseable request discarded ({}): {:?}", e,
                                       expired_cores_package.payload_data ().data));
                logger.debug (format! ("Stopping thread abnormally"));
                return None
            }
        };
        Some (StreamHandler {
            expired_cores_package,
            client_request_payload,
            hopper,
            resolver_arc,
            stream,
            logger
        })
    }

    pub fn go (&mut self) {
        // TODO: Put something in the ClientRequestPayload that directs the creation of the proper Framer here
        let framer = Box::new (HttpPacketFramer::new (Box::new (HttpResponseStartFinder {})));
        let socket_addr = {
            match StreamHandler::find_ip_addr (&self.resolver_arc, &self.client_request_payload.target_hostname, &self.logger) {
                Some (ip_addr) => SocketAddr::new (ip_addr, self.client_request_payload.target_port),
                None => {
                    self.send_cores_response(PlainData::new (SERVER_PROBLEM_RESPONSE), true);
                    self.logger.debug (format! ("Stopping thread after 503 for {}", self.summarize_request()));
                    return
                }
            }
        };
        match self.perform_stream_communications (socket_addr, framer) {
            Ok (()) => (),
            Err (_) => self.send_cores_response(PlainData::new (SERVER_PROBLEM_RESPONSE), true)
        };
    }

    fn perform_stream_communications (&mut self, addr: SocketAddr, framer: Box<Framer>) -> io::Result<()> {
        // TODO TEMPORARY UNTESTED CODE FOR SC-50 ONLY
        if addr.port () == 443 {
            self.logger.info (format! ("TEMPORARY: About to send {}-byte TLS packet to {}: {:?}",
                self.client_request_payload.data.data.len (), addr, &self.client_request_payload.data.data));
            return Ok(());
        }
        // TODO TEMPORARY UNTESTED CODE FOR SC-50 ONLY
        self.connect_stream (addr)?;
        let payload = self.client_request_payload.data.clone ();
        self.write_to_stream (addr, &payload)?;
        self.set_read_timeout(addr)?;
        self.transfer_from_stream(addr, framer)?;
        self.shut_down_stream().is_ok ();
        Ok(())
    }

    fn connect_stream (&mut self, addr: SocketAddr) -> io::Result<()> {
        self.logger.debug (format! ("Connecting stream to {} for {}", addr, self.summarize_request()));
        match self.stream.connect(addr) {
            Ok (s) => Ok (s),
            Err (e) => {
                self.logger.error (format! ("Could not connect to server at {} for {}: {}", addr,
                                            self.summarize_request(), e));
                Err (e)
            }
        }
    }

    fn write_to_stream (&mut self, addr: SocketAddr, payload: &PlainData) -> io::Result<usize> {
        self.logger.debug (format! ("Writing to stream for {}", self.summarize_request()));
        match self.stream.write (&payload.data[..]) {
            Ok (len) => Ok (len), // TODO: Maybe check return value against payload length
            Err (e) => {
                self.logger.error (format! ("Could not write to server at {} for {}: {}", addr,
                                            self.summarize_request (), e));
                self.error_shutdown (e)
            }
        }
    }

    fn set_read_timeout (&mut self, addr: SocketAddr) -> io::Result<()> {
        self.logger.debug (format! ("Setting stream timeout to {}ms for {}", RESPONSE_FINISHED_TIMEOUT_MS,
            self.summarize_request()));
        match self.stream.set_read_timeout(Some(Duration::from_millis(RESPONSE_FINISHED_TIMEOUT_MS))) {
            Ok (s) => Ok (s),
            Err (e) => {
                self.logger.error (format! ("Could not set read timeout on stream from {} for {}: {}", addr,
                                            self.summarize_request(), e));
                self.error_shutdown (e)
            }
        }
    }

    fn find_ip_addr (resolver_arc: &Arc<Mutex<Box<ResolverWrapper>>>, hostname: &String, logger: &Logger) -> Option<IpAddr> {
        let mut fqdn = hostname.clone ();
        fqdn.push ('.');
        match resolver_arc.lock ().expect ("Resolver is dead").lookup_ip (&fqdn[..]) {
            Ok (ref ip_addrs) if !ip_addrs.is_empty () => Some (ip_addrs[0]),
            Ok (_) => {
                logger.error (format! ("DNS search for hostname '{}' produced no results", fqdn));
                None
            },
            Err (_) => {
                logger.error (format! ("DNS search for hostname '{}' encountered error: invalid input", fqdn));
                None
            },
        }
    }

    fn transfer_from_stream (&mut self, addr: SocketAddr, mut framer: Box<Framer>) -> io::Result<()> {
        let mut buf: [u8; 16384] = [0; 16384];
        loop {
            match self.stream.read (&mut buf) {
                Ok (len) => {
                    self.logger.debug (format! ("Read {}-byte chunk from stream for {}: {}", len,
                                                self.summarize_request(), to_string (&Vec::from (&buf[0..len]))));
                    framer.add_data (&buf[0..len]);
                },
                Err (e) => {
                    self.logger.error (format! ("Could not read from server at {} for {}: {}", addr,
                                                self.summarize_request(), e));
                    return self.error_shutdown (e);
                }
            };
            loop {
                match framer.take_frame () {
                    Some (response_chunk) => {
                        self.logger.debug (format! ("Framed {}-byte {} response chunk for {}, '{}'", response_chunk.chunk.len (),
                                               if response_chunk.last_chunk {"final"} else {"non-final"},
                                                    self.summarize_request(), to_string (&response_chunk.chunk)));
                        self.send_cores_response(PlainData::new (&response_chunk.chunk[..]), response_chunk.last_chunk);
                        if response_chunk.last_chunk {return Ok (())}
                    },
                    None => {
                        self.logger.debug (format! ("Framer has no complete response chunk for {}",
                            self.summarize_request()));
                        break;
                    }
                }
            }
        }
    }

    fn shut_down_stream (&self) -> io::Result<()> {
        self.logger.debug (format! ("Shutting down stream for {}", self.summarize_request()));
        match self.stream.shutdown (Shutdown::Both) {
            Ok (s) => Ok (s),
            Err (e) => { self.logger.warning (format! ("Stream shutdown failure for {}: {}",
                                                       self.summarize_request (), e)); Err (e)}
        }
    }

    fn send_cores_response(&self, response_data: PlainData, last_response: bool) {
        let response_payload = ClientResponsePayload {
            stream_key: self.client_request_payload.stream_key,
            last_response,
            data: response_data
        };
        let incipient_cores_package =
            IncipientCoresPackage::new (self.expired_cores_package.remaining_route.clone (),
                response_payload, &self.client_request_payload.originator_public_key);
        self.hopper.send(incipient_cores_package).expect ("Hopper is dead");
    }

    fn error_shutdown<S> (&self, error: io::Error) -> io::Result<S> {
        self.stream.shutdown (Shutdown::Both).is_ok ();
        Err (error)
    }

    fn summarize_request (&self) -> String {
        http_packet_framer::summarize_http_packet (&self.client_request_payload.data.data)
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use trust_dns_resolver::error;
    use logger_trait_lib::logger::LoggerInitializerWrapper;
    use test_utils::test_utils::LoggerInitializerWrapperMock;
    use test_utils::test_utils::TestLogHandler;
    use resolver_wrapper::tests::ResolverWrapperMock;

    // Most of the tests for this code are in proxy_client.rs.  If a factory were written for this
    // struct, and that factory made an injectable collaborator of ProxyClient, some of the
    // functionality of ProxyClient's complicated tests could be moved in here.

    #[test]
    fn find_ip_addr_uses_dns_client () {
        LoggerInitializerWrapperMock::new ().init ();
        let logger = Logger::new ("Proxy Client");
        let hostname = String::from ("my.hostname.com");
        let mut lookup_ip_parameters_arc: Arc<Mutex<Vec<String>>> = Arc::new (Mutex::new (vec! ()));
        let resolver_wrapper = ResolverWrapperMock::new ()
            .lookup_ip_parameters (&mut lookup_ip_parameters_arc)
            .lookup_ip_result (Ok (vec! (IpAddr::from_str ("5.5.5.5").unwrap (),
                                         IpAddr::from_str ("6.6.6.6").unwrap ())));
        let resolver_arc: Arc<Mutex<Box<ResolverWrapper>>> = Arc::new (Mutex::new (Box::new (resolver_wrapper)));

        let result = StreamHandler::find_ip_addr(&resolver_arc, &hostname, &logger);

        assert_eq! (result.unwrap (), IpAddr::from_str ("5.5.5.5").unwrap ());
        let mut lookup_ip_parameters_guard = lookup_ip_parameters_arc.lock ().unwrap ();
        let lookup_ip_parameter = lookup_ip_parameters_guard.remove (0);
        assert_eq! (lookup_ip_parameter, String::from ("my.hostname.com."));
        assert_eq! (lookup_ip_parameters_guard.len (), 0);
    }

    #[test]
    fn find_ip_addr_returns_none_if_resolver_finds_no_addresses () {
        LoggerInitializerWrapperMock::new ().init ();
        let logger = Logger::new ("Proxy Client");
        let hostname = String::from ("my.hostname.com");
        let mut lookup_ip_parameters_arc: Arc<Mutex<Vec<String>>> = Arc::new (Mutex::new (vec! ()));
        let resolver_wrapper = ResolverWrapperMock::new ()
            .lookup_ip_parameters (&mut lookup_ip_parameters_arc)
            .lookup_ip_result (Ok (vec! ()));
        let resolver_arc: Arc<Mutex<Box<ResolverWrapper>>> = Arc::new (Mutex::new (Box::new (resolver_wrapper)));

        let result = StreamHandler::find_ip_addr(&resolver_arc, &hostname, &logger);

        assert_eq! (result, None);
        TestLogHandler::new ().exists_log_matching ("ThreadId\\(\\d+\\): ERROR: Proxy Client: DNS search for hostname 'my.hostname.com.' produced no results");
    }

    #[test]
    fn find_ip_addr_returns_none_if_resolver_throws_error () {
        LoggerInitializerWrapperMock::new ().init ();
        let logger = Logger::new ("Proxy Client");
        let hostname = String::from ("my.hostname.com");
        let mut lookup_ip_parameters_arc: Arc<Mutex<Vec<String>>> = Arc::new (Mutex::new (vec! ()));
        let resolver_wrapper = ResolverWrapperMock::new ()
            .lookup_ip_parameters (&mut lookup_ip_parameters_arc)
            .lookup_ip_result (Err (error::ResolveError::from (error::ResolveErrorKind::Message ("booga"))));
        let resolver_arc: Arc<Mutex<Box<ResolverWrapper>>> = Arc::new (Mutex::new (Box::new (resolver_wrapper)));

        let result = StreamHandler::find_ip_addr(&resolver_arc, &hostname, &logger);

        assert_eq! (result, None);
        TestLogHandler::new ().exists_log_matching ("ThreadId\\(\\d+\\): ERROR: Proxy Client: DNS search for hostname 'my.hostname.com.' encountered error: invalid input");
    }
}