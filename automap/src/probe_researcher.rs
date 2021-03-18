// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::automap_core_functions::{remove_firewall_hole, remove_permanent_firewall_hole};
use crate::comm_layer::Transactor;
use rand::{thread_rng, Rng};
use std::cell::Cell;
use std::fmt::{Display, Formatter};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::ops::Add;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::{fmt, thread};

//so far, println!() is safer for testing, with immediate feedback
#[allow(clippy::result_unit_err)]
pub fn close_exposed_port(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    params: FirstSectionData,
) -> Result<(), ()> {
    println!("Preparation for closing the forwarded port");
    match params.method {
        Method::Pmp | Method::Pcp | Method::Igdp(false) => {
            remove_firewall_hole(stdout, stderr, params)
        }
        Method::Igdp(true) => remove_permanent_firewall_hole(stdout, stderr, params),
    }
}

#[derive(PartialEq, Debug)]
pub enum Method {
    Pmp,
    Pcp,
    Igdp(bool),
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Method::Pmp => write!(f, "PMP protocol"),
            Method::Pcp => write!(f, "PCP protocol"),
            Method::Igdp(_flag) => write!(f, "IGDP protocol"),
        }
    }
}

//it was meant to be prepared for eventual collecting of errors but now it is ended with a merge and a single message
#[allow(clippy::type_complexity)]
pub fn prepare_router_or_report_failure(
    test_port: Option<u16>,
    test_pcp: Box<dyn FnOnce(Option<u16>) -> Result<(IpAddr, u16, Box<dyn Transactor>), String>>,
    test_pmp: Box<dyn FnOnce(Option<u16>) -> Result<(IpAddr, u16, Box<dyn Transactor>), String>>,
    test_igdp: Box<
        dyn FnOnce(Option<u16>) -> Result<(IpAddr, u16, Box<dyn Transactor>, bool), String>,
    >,
) -> Result<FirstSectionData, Vec<String>> {
    let mut collector: Vec<String> = vec![];
    match test_pcp(test_port) {
        Ok((ip, port, transactor)) => {
            return Ok(FirstSectionData {
                method: Method::Pcp,
                ip,
                port,
                transactor,
            })
        }
        Err(e) => collector.push(e),
    };
    match test_pmp(test_port) {
        Ok((ip, port, transactor)) => {
            return Ok(FirstSectionData {
                method: Method::Pmp,
                ip,
                port,
                transactor,
            })
        }
        Err(e) => collector.push(e),
    };
    match test_igdp(test_port) {
        Ok((ip, port, transactor, permanent)) => {
            return Ok(FirstSectionData {
                method: Method::Igdp(permanent),
                ip,
                port,
                transactor,
            })
        }
        Err(e) => collector.push(e),
    };
    if collector.len() == 3 {
        //this should be reworked in the future, processing the errors with more care
        collector.clear();
        collector.push(
            "\nNeither a PCP, PMP or IGDP protocol is being detected on your router \
         or something is wrong. \n\n"
                .to_string(),
        );
        Err(collector)
    } else {
        panic!("shouldn't happen")
    }
}

pub struct FirstSectionData {
    pub method: Method,
    pub ip: IpAddr,
    pub port: u16,
    pub transactor: Box<dyn Transactor>,
}

fn deploy_background_listener(
    port: u16,
    expected_nonce: u16,
    timeout_millis: u64,
) -> JoinHandle<Result<(), std::io::Error>> {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port)).unwrap();
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now().add(Duration::from_millis(timeout_millis));
        let mut stream = loop {
            if Instant::now() >= deadline {
                return Err(std::io::Error::from(ErrorKind::TimedOut));
            }
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e) => return Err(e),
            }
        };
        let mut buf = [0u8; 3];
        let mut buf_count = 0usize;
        stream.set_nonblocking(true)?;
        let deadline = Instant::now().add(Duration::from_millis(timeout_millis));
        loop {
            thread::sleep(Duration::from_millis(10));
            if Instant::now() >= deadline {
                return Err(std::io::Error::from(ErrorKind::TimedOut));
            }
            match stream.read(&mut buf[buf_count..]) {
                Ok(0) => {
                    let _ = stream.shutdown(Shutdown::Both);
                    if buf_count != 2 {
                        break Err(std::io::Error::from(ErrorKind::InvalidData));
                    }
                    let actual_nonce = ((buf[0] as u16) << 8) | (buf[1] as u16);
                    if actual_nonce == expected_nonce {
                        break Ok(());
                    }
                }
                Ok(len) => {
                    buf_count += len;
                }
                Err(e)
                    if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) =>
                {
                    continue
                }
                Err(e) => break Err(e),
            }
        }
    })
}

pub fn researcher_with_probe(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    server_address: SocketAddr,
    params: &mut FirstSectionData,
    server_response_timeout: u64,
) -> bool {
    write!(
        stdout,
        "\nTest of a port forwarded by using {} is starting. \n\n",
        params.method
    )
    .expect("write failed");

    let success_sign = Cell::new(false);
    evaluate_research(
        stdout,
        stderr,
        server_address,
        params,
        server_response_timeout,
        &success_sign,
    );

    stderr.flush().expect("failed to flush stdout");
    stdout.flush().expect("failed to flush stderr");

    success_sign.take()
}

pub fn evaluate_research(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    server_address: SocketAddr,
    params: &mut FirstSectionData,
    server_response_timeout: u64,
    success_sign: &Cell<bool>,
) {
    let nonce = generate_nonce();
    let thread_handle = deploy_background_listener(params.port, nonce, 3000);
    let http_request = format!(
        "GET /probe_request?ip={}&port={}&nonce={} HTTP/1.1\r\n\r\n",
        params.ip, params.port, nonce
    );
    let mut connection: TcpStream = match TcpStream::connect(server_address) {
        Ok(conn) => conn,
        Err(e) => {
            write!(
                stderr,
                "We couldn't connect to the \
             http server: {:?}. Test is terminating. ",
                e
            )
            .expect("writing failed");
            return;
        }
    };
    match connection.write_all(http_request.as_bytes()) {
        Ok(_) => (),
        Err(_) => {
            stderr
                .write_all(
                    b"Sending an http request to \
                 the server failed. Test is terminating. ",
                )
                .expect("writing failed");
            return;
        } // untested but safe
    }
    let mut buffer = [0u8; 1024];
    connection
        .set_read_timeout(Some(Duration::from_millis(server_response_timeout)))
        .expect("unsuccessful during setting nonblocking");
    let mut server_responded = false;
    match connection.read(&mut buffer) {
        Ok(length) => {
            stdout
                .write_all(&buffer[..length])
                .expect("writing server response failed");
            server_responded = true;
        }
        Err(e) if (e.kind() == ErrorKind::TimedOut) || (e.kind() == ErrorKind::WouldBlock) => {
            stderr
                .write_all(b"Request to the server was sent but no response came back. ")
                .expect("writing to stderr failed")
        }
        Err(e) => write!(
            stderr,
            "Request to the server was sent but reading the response failed: {:?} ",
            e
        )
        .expect("write!ing to stderr failed"),
    };
    if !server_responded {
        return;
    }
    match thread_handle.join() {
        Ok(Ok(_)) => {
            stdout
                .write_all(b"\n\nThe received nonce was evaluated to be a match; test passed. ")
                .expect("write_all failed");
            success_sign.set(true);
        }
        Ok(Err(e)) if e.kind() == ErrorKind::TimedOut => stdout
            .write_all(b"\n\nThe probe detector detected no incoming probe. ")
            .expect("write_all failed"),
        Ok(Err(e)) => write!(
            stdout,
            "\n\nThe probe detector ran into a problem: {:?}. ",
            e
        )
        .expect("write! failed"),
        Err(e) => {
            write!(stderr, "\n\nThe probe detector panicked: {:?}", e).expect("write_all failed")
        }
    }
}

fn generate_nonce() -> u16 {
    let mut rnd = thread_rng();
    rnd.gen_range(1000, 9999)
}

#[cfg(test)]
mod tests {
    use crate::comm_layer::pmp::PmpTransactor;
    use crate::probe_researcher::mock_tools::{
        mock_router_common_test_finding_ip_and_doing_mapping, mock_router_common_test_unsuccessful,
        mock_router_igdp_test_unsuccessful, test_stream_acceptor_and_probe,
        test_stream_acceptor_and_probe_8875_imitator, u16_to_byte_array, MockStream,
    };
    use crate::probe_researcher::{
        deploy_background_listener, generate_nonce, prepare_router_or_report_failure,
        researcher_with_probe, FirstSectionData, Method,
    };
    use masq_lib::utils::{find_free_port, localhost};
    use std::io::{ErrorKind, Read};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::str::FromStr;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn prepare_router_or_report_failure_retrieves_ip() {
        let result = prepare_router_or_report_failure(
            None,
            Box::new(mock_router_common_test_unsuccessful),
            Box::new(mock_router_common_test_finding_ip_and_doing_mapping),
            Box::new(mock_router_igdp_test_unsuccessful),
        );

        //sadly not all of those types implementing Transactor can implement PartialEq each
        assert!(result.is_ok());
        let unwrapped_result = result.unwrap();
        assert_eq!(unwrapped_result.ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(unwrapped_result.method, Method::Pmp);
        assert_eq!(unwrapped_result.port, 4444);
        //proof that I received an implementer of Transactor
        let _downcast_value: &PmpTransactor =
            unwrapped_result.transactor.as_any().downcast_ref().unwrap();
    }

    // TODO rework this test; it aged. We gather results from each module laboriously and then we provide a simple message as some kind of summary.
    // Or make it clear that it should test something else ideally
    #[test]
    fn prepare_router_or_report_failure_reports_of_accumulated_errors() {
        let result = prepare_router_or_report_failure(
            None,
            Box::new(mock_router_common_test_unsuccessful),
            Box::new(mock_router_common_test_unsuccessful),
            Box::new(mock_router_igdp_test_unsuccessful),
        );

        assert_eq!(
            result.err().unwrap(),
            vec![
                "\nNeither a PCP, PMP or IGDP protocol is being detected on your router or something is wrong. \n\n"
            ]
        )
    }

    #[test]
    fn deploy_background_listener_with_good_probe_works() {
        let port = find_free_port();

        let handle = deploy_background_listener(port, 8875, 500);

        let send_probe_addr = SocketAddr::new(localhost(), port);

        test_stream_acceptor_and_probe_8875_imitator(0, send_probe_addr);

        let result = handle.join();
        match result {
            Ok(Ok(())) => (),
            x => panic!("Expected Ok(Ok(())), got {:?}", x),
        }
    }

    #[test]
    fn deploy_background_listener_complains_about_probe_of_insufficient_length() {
        let port = find_free_port();
        let handle = deploy_background_listener(port, 8875, 500);
        let send_probe_addr = SocketAddr::new(localhost(), port);
        let mut probe = Vec::from(u16_to_byte_array(8875));
        probe.remove(1); // One byte too few

        test_stream_acceptor_and_probe(probe.as_slice(), 0, send_probe_addr);

        let result = handle.join();
        match result {
            Ok(Err(e)) if (e.kind() == ErrorKind::InvalidData) => (),
            x => panic!("Expected Ok(Err(InvalidData)), got {:?}", x),
        }
    }

    #[test]
    fn deploy_background_listener_complains_about_probe_of_excessive_length() {
        let port = find_free_port();
        let handle = deploy_background_listener(port, 8875, 500);
        let send_probe_addr = SocketAddr::new(localhost(), port);
        let mut probe = Vec::from(u16_to_byte_array(8875));
        probe.push(0xFF); // one byte too long

        test_stream_acceptor_and_probe(probe.as_slice(), 0, send_probe_addr);

        let result = handle.join();
        match result {
            Ok(Err(e)) if (e.kind() == ErrorKind::InvalidData) => (),
            x => panic!("Expected Ok(Err(InvalidData)), got {:?}", x),
        }
    }

    #[test]
    fn deploy_background_listener_without_getting_probe_propagates_that_fact_correctly_after_connection_interrupted(
    ) {
        let port = find_free_port();
        let handle = deploy_background_listener(port, 8875, 500);
        let send_probe_addr = SocketAddr::new(localhost(), port);

        test_stream_acceptor_and_probe(&[], 0, send_probe_addr);

        let result = handle.join();
        match result {
            Ok(Err(e)) if e.kind() == ErrorKind::BrokenPipe => (),
            Ok(Err(e)) if e.kind() == ErrorKind::InvalidData => (),
            x => panic!(
                "Expected Ok(Err(BrokenPipe)) or Ok(Err(InvalidData)); got {:?}",
                x
            ),
        }
    }

    #[test]
    fn deploy_background_listener_without_getting_probe_terminates_alone_after_connection_lasts_too_long(
    ) {
        let port = find_free_port();
        let handle = deploy_background_listener(port, 8875, 200);
        let send_probe_addr = SocketAddr::new(localhost(), port);
        test_stream_acceptor_and_probe(&[], 500, send_probe_addr);

        let result = handle.join();

        match result {
            Ok(Err(e)) if e.kind() == ErrorKind::TimedOut => (),
            x => panic!("Expected Ok(Err(TimedOut)); got {:?}", x),
        }
    }

    #[test]
    fn deploy_background_listener_ends_its_job_after_waiting_period_for_any_connection_but_none_was_sensed(
    ) {
        let handle = deploy_background_listener(7004, 1234, 10);

        let result = handle.join();
        match result {
            Ok(Err(e)) if e.kind() == ErrorKind::TimedOut => (),
            x => panic!("Expected Ok(Err(TimedOut)), got {:?}", x),
        }
    }

    #[test]
    fn generate_nonce_works() {
        (1..100).for_each(|_| {
            let nonce = generate_nonce();
            assert!(10000 > nonce && nonce > 999)
        });
    }

    #[test]
    fn researcher_with_probe_returns_failure_if_cannot_connect_to_the_http_server() {
        let mut stdout = MockStream::new();
        let mut stderr = MockStream::new();
        let port = find_free_port();
        let mut parameters = FirstSectionData {
            method: Method::Pmp,
            ip: IpAddr::V4(Ipv4Addr::from_str("0.0.0.0").unwrap()),
            port,
            transactor: Box::new(PmpTransactor::default()),
        };
        let server_address = SocketAddr::from_str("0.0.0.0:7010").unwrap();

        let result = researcher_with_probe(
            &mut stdout,
            &mut stderr,
            server_address,
            &mut parameters,
            1500,
        );
        assert_eq!(result, false);
        assert!(
            stderr
                .stream
                .starts_with("We couldn\'t connect to the http server: "),
            "{}",
            stderr.stream
        );
        assert!(
            stderr.stream.ends_with(". Test is terminating. "),
            "{}",
            stderr.stream
        );
        assert_eq!(
            stdout.stream,
            "\nTest of a port forwarded by using PMP protocol is starting. \n\n"
        );
        assert_eq!(stdout.flush_count, 1);
        assert_eq!(stderr.flush_count, 1);
    }

    #[test]
    fn researcher_with_probe_sends_http_request_and_returns_failure_for_no_response_ever_coming_back(
    ) {
        let mut stdout = MockStream::new();
        let mut stderr = MockStream::new();

        let server_address = SocketAddr::new(localhost(), find_free_port());
        //fake server
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let listener = TcpListener::bind(server_address).unwrap();
            tx.send(()).unwrap();
            let (mut connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut buf = [0u8; 1024];
            connection.read(&mut buf).unwrap();
            thread::sleep(Duration::from_millis(3000))
        });

        let mut parameters = FirstSectionData {
            method: Method::Pmp,
            ip: localhost(),
            port: find_free_port(),
            transactor: Box::new(PmpTransactor::default()),
        };

        rx.recv().unwrap();
        let result = researcher_with_probe(
            &mut stdout,
            &mut stderr,
            server_address,
            &mut parameters,
            10,
        );
        assert_eq!(result, false);
        assert_eq!(
            stdout.stream,
            "\nTest of a port forwarded by using PMP protocol is starting. \n\n"
        );
        assert!(
            stderr
                .stream
                .starts_with("Request to the server was sent but no "),
            "{}",
            stderr.stream
        );
        assert_eq!(stdout.flush_count, 1);
        assert_eq!(stderr.flush_count, 1);
    }
}

pub mod mock_tools {
    use super::*;
    use crate::comm_layer::pmp::PmpTransactor;
    use std::io::IoSlice;

    pub fn mock_router_common_test_finding_ip_and_doing_mapping(
        _port: Option<u16>,
    ) -> Result<(IpAddr, u16, Box<dyn Transactor>), String> {
        Ok((
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            4444,
            Box::new(PmpTransactor::new()),
        ))
    }

    pub fn mock_router_common_test_unsuccessful(
        _port: Option<u16>,
    ) -> Result<(IpAddr, u16, Box<dyn Transactor>), String> {
        Err(String::from("Test ended unsuccessfully"))
    }

    pub fn mock_router_igdp_test_unsuccessful(
        _port: Option<u16>,
    ) -> Result<(IpAddr, u16, Box<dyn Transactor>, bool), String> {
        Err(String::from("Test ended unsuccessfully"))
    }

    pub fn test_stream_acceptor_and_probe_8875_imitator(
        shutdown_delay_millis: u64,
        send_probe_socket: SocketAddr,
    ) {
        let message = u16_to_byte_array(8875);
        test_stream_acceptor_and_probe(&message, shutdown_delay_millis, send_probe_socket);
    }

    pub fn test_stream_acceptor_and_probe(
        probe: &[u8],
        shutdown_delay_millis: u64,
        send_probe_socket: SocketAddr,
    ) {
        let mut connection = TcpStream::connect(send_probe_socket).unwrap();
        if !probe.is_empty() {
            connection.write_all(probe).unwrap();
        } else if shutdown_delay_millis == 0 {
            connection.shutdown(Shutdown::Both).unwrap();
        } else {
            thread::sleep(Duration::from_millis(shutdown_delay_millis));
        }
    }

    pub fn u16_to_byte_array(x: u16) -> [u8; 2] {
        let b1: u8 = ((x >> 8) & 0xff) as u8;
        let b2: u8 = (x & 0xff) as u8;
        [b1, b2]
    }

    pub struct MockStream {
        pub stream: String,
        pub flush_count: u8,
    }

    #[allow(clippy::new_without_default)]
    impl MockStream {
        pub fn new() -> Self {
            Self {
                stream: String::new(),
                flush_count: 0,
            }
        }
    }

    impl Write for MockStream {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            unimplemented!()
        }

        fn write_vectored(&mut self, _bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
            unimplemented!()
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flush_count += 1;
            Ok(())
        }

        fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
            self.stream.push_str(std::str::from_utf8(buf).unwrap());
            Ok(())
        }

        fn by_ref(&mut self) -> &mut Self
        where
            Self: Sized,
        {
            unimplemented!()
        }
    }
}
