// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::{thread};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::ops::Add;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use log::{info, error};

use rand::{Rng, thread_rng};

use crate::automap_core_functions::{TestParameters, TestStatus};
use crate::comm_layer::{Method, Transactor, AutomapError, AutomapErrorCause};

// //it was meant to be prepared for eventual collecting of errors but now it is ended with a merge and a single message
// #[allow(clippy::type_complexity)]
// pub fn prepare_router_or_report_failure(
//     protocol: &Method,
//     tester: Tester,
//     parameters: &mut TestParameters,
// ) -> Result<Vec<FirstSectionData>, Vec<String>> {
//     let result = match tester(test_port, port_is_manual) {
//         Ok((ip, port, transactor, permanent_only)) => {
//             Ok(FirstSectionData {
//                 method: transactor.method(),
//                 permanent_only: Some(permanent_only),
//                 ip,
//                 port_is_manual,
//                 port,
//                 transactor,
//             })
//         }
//         Err(e) => Err(e),
//     }
//     .collect::<Vec<Result<FirstSectionData, String>>>();
//     let (successes, _failures) = results.into_iter().fold ((vec![], vec![]), |so_far, result| {
//         match result {
//             Ok(success) => (plus(so_far.0, success), so_far.1),
//             Err(failure) => (so_far.0, plus (so_far.1, failure)),
//         }
//     });
//     if successes.is_empty() {
//         //this should be reworked in the future, processing the errors with more care
//         Err (vec!["\nNeither a PCP, PMP or IGDP protocol is being detected on your router \
//          or something is wrong. \n\n".to_string()])
//     } else {
//         Ok(successes)
//     }
// }

#[derive (Debug)]
pub struct FirstSectionData {
    pub method: Method,
    pub permanent_only: Option<bool>,
    pub ip: IpAddr,
    pub port: u16,
    pub port_is_manual: bool,
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

// pub fn researcher_with_probe(
//     stdout: &mut dyn Write,
//     stderr: &mut dyn Write,
//     server_address: SocketAddr,
//     params: &mut FirstSectionData,
//     server_response_timeout: u64,
// ) -> bool {
//     write!(
//         stdout,
//         "\nTest of a port forwarded by using {} is starting. \n\n",
//         params.method
//     )
//     .expect("write failed");
//
//     let success_sign = Cell::new(false);
//     request_probe(
//         stdout,
//         stderr,
//         server_address,
//         params,
//         server_response_timeout,
//         &success_sign,
//     );
//
//     stderr.flush().expect("failed to flush stdout");
//     stdout.flush().expect("failed to flush stderr");
//
//     success_sign.take()
// }

pub fn request_probe(
    status: TestStatus,
    parameters: &TestParameters,
    public_ip: IpAddr,
    server_response_timeout: u64,
    probe_timeout: u64
) -> TestStatus {
    if status.fatal {
        return status;
    }
    let nonce = generate_nonce();
    info!(
        "{}. Deploying the listener for the incoming probe to {}:{} with nonce {} to time out after {}ms",
        status.step, public_ip, parameters.hole_port, nonce, probe_timeout
    );
    let thread_handle = deploy_background_listener(parameters.hole_port, nonce, probe_timeout);
    let status = status.succeed();
    let http_request = format!(
        "GET /probe_request?ip={}&port={}&nonce={} HTTP/1.1\r\n\r\n",
        public_ip, parameters.hole_port, nonce
    );
    info!(
        "{}. Connecting to probe server at {}",
        status.step, parameters.probe_server_address
    );
    let mut connection: TcpStream = match TcpStream::connect(parameters.probe_server_address) {
        Ok(conn) => conn,
        Err(e) => {
            error!("...failed: {:?}", e);
            return status.fail (AutomapError::ProbeServerConnectError(format!("{:?}", e)))
        }
    };
    let status = status.succeed();
    match connection.write_all(http_request.as_bytes()) {
        Ok(_) => (),
        Err(e) => {
            error!("...failed: {:?}", e);
            return status.fail (AutomapError::ProbeRequestError(AutomapErrorCause::ProbeServerIssue, format!("{:?}", e)))
        }
    }
    let status = status.succeed();
    let mut buffer = [0u8; 1024];
    connection
        .set_read_timeout(Some(Duration::from_millis(server_response_timeout)))
        .expect("unsuccessful during setting nonblocking");
    info!(
        "{}. Requesting probe with nonce {}",
        status.step, nonce
    );
    match connection.read(&mut buffer) {
        Ok(length) if length == 0 => {
            error!("...failed. Probe server closed the connection unexpectedly.");
            return status.fail(AutomapError::ProbeRequestError(AutomapErrorCause::ProbeServerIssue, "Zero-length response".to_string()))
        }
        Ok(length) => {
            let response = String::from_utf8(buffer[0..length].to_vec()).expect("Bad UTF-8 from probe server");
            if response.starts_with("200:") {
                ()
            }
            else {
                error!("...failed. Probe server could not probe: {}", response);
                return status.fail(AutomapError::ProbeRequestError(AutomapErrorCause::ProbeFailed, response))
            }
        }
        Err(e) if (e.kind() == ErrorKind::TimedOut) || (e.kind() == ErrorKind::WouldBlock) => {
            error!("...timed out after {}ms waiting for response from probe server", server_response_timeout);
            return status.fail(AutomapError::ProbeRequestError(AutomapErrorCause::ProbeFailed, format!("Timeout awaiting response: {}ms", server_response_timeout)))
        }
        Err(e) => {
            error!("...failed: {:?}", e);
            return status.fail(AutomapError::ProbeRequestError(AutomapErrorCause::ProbeServerIssue, format!("Error receiving response: {:?}", e)))
        },
    };
    let status = status.succeed();
    info!(
        "{}. Awaiting notification from listener that probe has arrived",
        status.step
    );
    match thread_handle.join() {
        Ok(Ok(_)) => (),
        Ok(Err(e)) if e.kind() == ErrorKind::TimedOut => {
            error!("...but after {}ms probe had not yet arrived.", probe_timeout);
            return status.fail(AutomapError::ProbeReceiveError(format!("Timeout {}ms", probe_timeout)))
        },
        Ok(Err(e)) => {
            error!("...failure receiving probe: {:?}", e);
            return status.fail(AutomapError::ProbeReceiveError(format!("{:?}", e)))
        },
        Err(e) => {
            error!("...failure. The probe detector panicked: {:?}", e);
            return status.fail(AutomapError::ProbeReceiveError(format!("{:?}", e)))
        }
    }
    status.succeed()
}

fn generate_nonce() -> u16 {
    let mut rnd = thread_rng();
    rnd.gen_range(1000, 9999)
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind};

    use masq_lib::utils::{find_free_port, localhost};

    use crate::probe_researcher::{
        deploy_background_listener, generate_nonce,
    };
    use crate::probe_researcher::mock_tools::{
        test_stream_acceptor_and_probe, test_stream_acceptor_and_probe_8875_imitator, u16_to_byte_array,
    };
    use std::net::SocketAddr;

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
}

pub mod mock_tools {
    use std::io::IoSlice;

    use crate::comm_layer::pmp::PmpTransactor;

    use super::*;

    pub fn mock_router_common_test_finding_ip_and_doing_mapping(
        _port: u16,
        _port_is_manual: bool,
    ) -> Result<(IpAddr, u16, Box<dyn Transactor>, bool), String> {
        Ok((
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            4444,
            Box::new(PmpTransactor::new()),
            false,
        ))
    }

    pub fn mock_router_common_test_unsuccessful(
        _port: u16,
        _port_is_manual: bool,
    ) -> Result<(IpAddr, u16, Box<dyn Transactor>, bool), String> {
        Err(String::from("Test ended unsuccessfully"))
    }

    pub fn mock_router_igdp_test_unsuccessful(
        _port: u16,
        _port_is_manual: bool,
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
