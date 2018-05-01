// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use std::str::FromStr;
use std::net::IpAddr::V4;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use sub_lib::main_tools::StdStreams;
use sub_lib::socket_server::SocketServer;
use sub_lib::udp_socket_wrapper::UdpSocketWrapperTrait;
use sub_lib::udp_socket_wrapper::UdpSocketWrapperReal;
use sub_lib::limiter::Limiter;
use sub_lib::logger::Logger;
use processor::ProcessorReal;
use packet_server::PacketServerTrait;
use packet_server::PacketServerReal;

pub struct DnsSocketServer<S> where S: UdpSocketWrapperTrait {
    dns_target: Option<IpAddr>,
    socket_wrapper: S,
    pub limiter: Limiter
}

impl<S> SocketServer for DnsSocketServer<S> where S: UdpSocketWrapperTrait {
    fn name(&self) -> String {
        String::from("EntryDnsServer")
    }

    fn initialize_as_root (&mut self, args: &Vec<String>, _streams: &mut StdStreams) {
        self.dns_target = Some (get_dns_target (args));
        let socket_addr = SocketAddr::new (V4 (Ipv4Addr::from (0)), get_dns_port (args));
        // The following expect() will cause an appropriate panic if the port can't be opened
        self.socket_wrapper.bind (socket_addr).expect (&format! ("Cannot bind socket to {:?}", socket_addr));
    }

    fn serve_without_root (&mut self) {
        let processor = ProcessorReal::new (self.dns_target.expect("Missing dns_target - was initialize_as_root called?"));
        let mut packet_server = PacketServerReal {logger: Logger::new ("EntryDnsServer"),
            socket: &mut self.socket_wrapper, processor: &processor};
        let mut buf: [u8; 65536] = [0; 65536];
        while self.limiter.should_continue () {
            packet_server.serve (&mut buf);
        }
    }
}

// TODO: why not use the `::new` convention?
pub fn new_dns_socket_server() -> DnsSocketServer<UdpSocketWrapperReal> {
    DnsSocketServer {dns_target: None, socket_wrapper: UdpSocketWrapperReal::new (), limiter: Limiter::new()}
}

fn get_dns_target (args: &Vec<String>) -> IpAddr {
    let finder = ParameterFinder::new (args);
    let ip_addr_str = match finder.find_value_after ("--dns_target", "must be followed by IP address to redirect to (default 127.0.0.1)") {
        Some (s) => s,
        None => String::from ("127.0.0.1")
    };
    match Ipv4Addr::from_str(&ip_addr_str) {
        Ok (ip_addr) => V4 (ip_addr),
        Err (_) => panic! ("Invalid IP address for --dns_target: {}", ip_addr_str)
    }
}

fn get_dns_port (args: &Vec<String>) -> u16 {
    let finder = ParameterFinder::new (args);
    let port_str = match finder.find_value_after("--dns_port", "must be followed by port number on which DNS server listens (default 53)") {
        Some (s) => s,
        None => String::from("53")
    };
    let port: u64 = match port_str.parse() {
        Ok (p) => p,
        Err (_) => panic! ("DNS server port must be numeric, not '{}'", port_str)
    };
    if port < 1 || port > 65535 {
        panic! ("DNS server port must be in the range 1-65535, not {}", port)
    }
    port as u16
}

struct ParameterFinder<'a> {
    args: &'a Vec<String>
}

impl<'a> ParameterFinder<'a> {
    fn new (args: &'a Vec<String>) -> ParameterFinder<'a> {
        ParameterFinder {args}
    }

    fn find_value_after (&self, parameter_tag: &str, msg: &str) -> Option<String> {
        let mut index = 0;
        while index < self.args.len() {
            if self.args[index] == parameter_tag {
                if index == self.args.len () - 1 {
                    // crashpoint - return none?
                    panic! ("{} {}", parameter_tag, msg);
                }
                let value: &str = &self.args[index+1];
                if value.starts_with ("-") {
                    // crashpoint - return none?
                    panic! ("{} {}", parameter_tag, msg);
                } else {
                    return Some (String::from (value))
                }
            }
            // TODO: Should probably skip 2 if this item had a parameter
            index += 1;
        }
        return None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::time::Duration;
    use std::cell::RefCell;
    use std::ops::DerefMut;
    use std::cmp::min;
    use test_utils::test_utils::FakeStreamHolder;
    use sub_lib::packet_facade::PacketFacade;
    use logger_trait_lib::logger::LoggerInitializerWrapper;
    use test_utils::test_utils::LoggerInitializerWrapperMock;
    use test_utils::test_utils::TestLogHandler;

    struct UdpSocketWrapperMockGuts {
        log: Vec<String>,
        buf: [u8; 12]
    }

    struct UdpSocketWrapperMock {
        guts: RefCell<UdpSocketWrapperMockGuts>
    }

    impl UdpSocketWrapperTrait for UdpSocketWrapperMock {
        fn bind(&mut self, addr: SocketAddr) -> io::Result<bool> {
            let mut guts_ref = self.guts.borrow_mut ();
            let guts: &mut UdpSocketWrapperMockGuts = guts_ref.deref_mut ();
            guts.log.push (format! ("bind ('{:?}')", addr));
            Ok (true)
        }

        fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            // Don't really care about this call in this code
            Ok (())
        }

        fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let mut guts_ref = self.guts.borrow_mut ();
            let guts: &mut UdpSocketWrapperMockGuts = guts_ref.deref_mut ();
            guts.log.push(format!("recv_from (buf)"));
            UdpSocketWrapperMock::copy (buf, &guts.buf);
            Ok((guts.buf.len(), SocketAddr::from_str("0.0.0.0:0").unwrap()))
        }

        fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
            let mut guts_ref = self.guts.borrow_mut ();
            let guts: &mut UdpSocketWrapperMockGuts = guts_ref.deref_mut ();
            guts.log.push (format! ("send_to (buf, {:?})", addr));
            UdpSocketWrapperMock::copy (&mut guts.buf, buf);
            Ok (buf.len ())
        }
    }
    
    impl UdpSocketWrapperMock {
        fn new (buf: &[u8]) -> UdpSocketWrapperMock {
            assert_eq! (buf.len () <= 12, true, "Mock accepts buffer of up to 12 bytes, not {}", buf.len ());
            let result = UdpSocketWrapperMock {
                guts: RefCell::new (UdpSocketWrapperMockGuts {
                    log: Vec::new (),
                    buf: [0; 12]
                })
            };
            result.guts.borrow_mut ().deref_mut ().buf.copy_from_slice (&buf);
            result
        }

        fn copy (destination: &mut [u8], source: &[u8]) {
            let to_copy = min (destination.len (), source.len ());
            for i in 0..to_copy {
                destination[i] = source[i];
            }
        }
    }

    #[test]
    fn knows_its_name () {
        let subject = new_dns_socket_server ();

        let result = subject.name ();

        assert_eq! (&result, "EntryDnsServer");
    }

    #[test]
    #[should_panic (expected = "--dns_target must be followed by IP address to redirect to (default 127.0.0.1)")]
    fn complains_about_missing_dns_target () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_target"), String::from ("--something_else")),
                                   &mut holder.streams ());
    }

    #[test]
    #[should_panic (expected = "--dns_target must be followed by IP address to redirect to (default 127.0.0.1)")]
    fn complains_about_missing_dns_target_at_end () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("irrelevant"), String::from ("--dns_target")),
                                   &mut holder.streams ());
    }

    #[test]
    #[should_panic (expected = "Invalid IP address for --dns_target: lots.and.lots.of.dots")]
    fn complains_about_dns_target_with_too_many_dots () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_target"), String::from ("lots.and.lots.of.dots")),
                                   &mut holder.streams ());
    }

    #[test]
    #[should_panic (expected = "Invalid IP address for --dns_target: only.two.dots")]
    fn complains_about_dns_target_with_too_few_dots () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_target"), String::from ("only.two.dots")),
                                   &mut holder.streams ());
    }

    #[test]
    #[should_panic (expected = "Invalid IP address for --dns_target: 123.124.125.booga")]
    fn complains_about_dns_target_with_nonnumeric_components () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_target"), String::from ("123.124.125.booga")),
                                   &mut holder.streams ());
    }

    #[test]
    #[should_panic (expected = "Invalid IP address for --dns_target: 123.124.125.256")]
    fn complains_about_dns_target_with_numeric_components_too_large () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_target"), String::from ("123.124.125.256")),
                                   &mut holder.streams ());
    }

    #[test]
    fn accepts_valid_dns_target () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_target"), String::from ("123.124.125.126")),
                                   &mut holder.streams ());

        assert_eq! (subject.dns_target, Some (V4(Ipv4Addr::from_str ("123.124.125.126").unwrap ())));
    }

    #[test]
    fn defaults_unspecified_dns_target () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(), &mut holder.streams ());

        assert_eq! (subject.dns_target, Some (V4(Ipv4Addr::from_str ("127.0.0.1").unwrap ())));
    }

    #[test]
    #[should_panic (expected = "--dns_port must be followed by port number on which DNS server listens (default 53)")]
    fn complains_about_missing_dns_port () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_port"), String::from ("--something_else")),
                                   &mut holder.streams ());
    }

    #[test]
    #[should_panic (expected = "DNS server port must be numeric, not 'booga'")]
    fn complains_if_dns_server_port_is_not_numeric () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_port"), String::from ("booga")),
                                   &mut holder.streams ());
    }

    #[test]
    #[should_panic (expected = "DNS server port must be in the range 1-65535, not 0")]
    fn complains_if_dns_server_port_is_too_small () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_port"), String::from ("0")),
                                   &mut holder.streams ());

        panic! ("Wrong message");
    }

    #[test]
    #[should_panic (expected = "DNS server port must be in the range 1-65535, not 65536")]
    fn complains_if_dns_server_port_is_too_large () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_port"), String::from ("65536")),
                                   &mut holder.streams ());

        panic! ("Wrong message");
    }

    #[test]
    fn accepts_valid_dns_port () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(String::from ("--dns_port"), String::from ("5454")),
                                   &mut holder.streams ());

        let socket_wrapper = &subject.socket_wrapper as &UdpSocketWrapperMock;
        let log = &socket_wrapper.guts.borrow ().log;
        assert_eq! (log[0], "bind ('V4(0.0.0.0:5454)')")
    }

    #[test]
    fn defaults_unspecified_dns_port () {
        let mut holder = FakeStreamHolder::new ();
        let mut subject = make_instrumented_subject ();;

        subject.initialize_as_root(&vec!(),
                                   &mut holder.streams ());

        let socket_wrapper = &subject.socket_wrapper as &UdpSocketWrapperMock;
        let log = &socket_wrapper.guts.borrow ().log;
        assert_eq! (log[0], "bind ('V4(0.0.0.0:53)')")
    }

    #[test]
    fn serves_a_single_request () {
        let (log, mut buf) = {
            LoggerInitializerWrapperMock::new ().init ();
            let mut subject = make_instrumented_subject();
            subject.dns_target = Some(V4(Ipv4Addr::from_str("1.2.3.4").unwrap()));
            subject.limiter = Limiter::with_only (1);

            subject.serve_without_root();

            let log = &subject.socket_wrapper.guts.borrow ().log;
            let buf = &subject.socket_wrapper.guts.borrow ().buf;
            (log.clone (), buf.clone ())
        };

        assert_eq! (&log, &vec! (
            String::from ("recv_from (buf)"),
            String::from ("send_to (buf, V4(0.0.0.0:0))")
        ));
        let facade = PacketFacade::new (&mut buf, 12);
        assert_eq! (facade.get_transaction_id (), Some (0x1234));
        assert_eq! (facade.get_rcode (), Some (0x4));
        TestLogHandler::new ().exists_log_matching (r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d ThreadId\(\d+\): INFO: EntryDnsServer: \d+ns: 0\.0\.0\.0:0 RQF \(\) -> RS4 \(\)");
    }

    fn make_instrumented_subject () -> DnsSocketServer<UdpSocketWrapperMock> {
        let socket_wrapper = UdpSocketWrapperMock::new (&[
            0x12, 0x34, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]);
        DnsSocketServer {dns_target: None, socket_wrapper, limiter: Limiter::with_only (1)}
    }
}