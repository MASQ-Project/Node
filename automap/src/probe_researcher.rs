// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::ops::Add;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rand::{thread_rng, Rng};

use crate::automap_core_functions::{TestParameters, TestStatus};
use crate::comm_layer::{AutomapError, AutomapErrorCause, Transactor};
use masq_lib::utils::AutomapProtocol;

#[derive(Debug)]
pub struct FirstSectionData {
    pub method: AutomapProtocol,
    pub permanent_only: Option<bool>,
    pub ip: IpAddr,
    pub port: u16,
    pub port_is_manual: bool,
    pub transactor: Box<dyn Transactor>,
}

fn deploy_background_listener(
    status: TestStatus,
    port: u16,
    expected_nonce: u16,
    timeout_millis: u64,
) -> (JoinHandle<Result<(), std::io::Error>>, TestStatus) {
    if status.fatal {
        return (thread::spawn(move || Ok(())), status);
    }
    let status = status.begin_attempt(format! ("Deploying the listener for the incoming probe to port {} with nonce {} to time out after {}ms",
        port, expected_nonce, timeout_millis));
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let join_handle = thread::spawn(move || {
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
    });
    (join_handle, status.succeed())
}

pub fn request_probe(
    status: TestStatus,
    parameters: &TestParameters,
    public_ip: IpAddr,
    server_response_timeout: u64,
    probe_timeout: u64,
) -> TestStatus {
    if status.fatal {
        return status;
    }
    let nonce = generate_nonce();
    let (thread_handle, status) =
        deploy_background_listener(status, parameters.hole_port, nonce, probe_timeout);
    let status = status.begin_attempt(format!(
        "Connecting to probe server at {}",
        parameters.probe_server_address
    ));
    let mut connection: TcpStream = match TcpStream::connect(parameters.probe_server_address) {
        Ok(conn) => conn,
        Err(e) => return status.fail(AutomapError::ProbeServerConnectError(format!("{:?}", e))),
    };
    let status = status.succeed();
    let status = status.begin_attempt(format!(
        "Requesting probe with nonce {} from probe server",
        nonce
    ));
    let http_request = format!(
        "GET /probe_request?ip={}&port={}&nonce={} HTTP/1.1\r\n\r\n",
        public_ip, parameters.hole_port, nonce
    );
    match connection.write_all(http_request.as_bytes()) {
        Ok(_) => (),
        Err(e) => {
            return status.fail(AutomapError::ProbeRequestError(
                AutomapErrorCause::ProbeServerIssue,
                format!("{:?}", e),
            ))
        }
    }
    let status = status.succeed();
    let mut buffer = [0u8; 1024];
    connection
        .set_read_timeout(Some(Duration::from_millis(server_response_timeout)))
        .expect("unsuccessful during setting nonblocking");
    let status =
        status.begin_attempt("Reading probe server's report about the probe attempt".to_string());
    match connection.read(&mut buffer) {
        Ok(0) => {
            return status.fail(AutomapError::ProbeRequestError(
                AutomapErrorCause::ProbeServerIssue,
                "Zero-length response".to_string(),
            ))
        }
        Ok(length) => {
            let response =
                String::from_utf8(buffer[0..length].to_vec()).expect("Bad UTF-8 from probe server");
            if !response.contains("200 OK") {
                return status.fail(AutomapError::ProbeRequestError(
                    AutomapErrorCause::ProbeFailed,
                    response,
                ));
            }
        }
        Err(e) if (e.kind() == ErrorKind::TimedOut) || (e.kind() == ErrorKind::WouldBlock) => {
            return status.fail(AutomapError::ProbeRequestError(
                AutomapErrorCause::ProbeFailed,
                format!("Timeout awaiting response: {}ms", server_response_timeout),
            ))
        }
        Err(e) => {
            return status.fail(AutomapError::ProbeRequestError(
                AutomapErrorCause::ProbeServerIssue,
                format!("Error receiving response: {:?}", e),
            ))
        }
    };
    let status = status.succeed();
    let status = status
        .begin_attempt("Awaiting notification from listener that probe has arrived".to_string());
    match thread_handle.join() {
        Ok(Ok(_)) => (),
        Ok(Err(e)) if e.kind() == ErrorKind::TimedOut => {
            return status.fail(AutomapError::ProbeReceiveError(format!(
                "Timeout {}ms",
                probe_timeout
            )))
        }
        Ok(Err(e)) => return status.fail(AutomapError::ProbeReceiveError(format!("{:?}", e))),
        Err(e) => return status.fail(AutomapError::ProbeReceiveError(format!("{:?}", e))),
    }
    status.succeed()
}

fn generate_nonce() -> u16 {
    let mut rnd = thread_rng();
    rnd.gen_range(1000..=9999)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    use masq_lib::utils::{find_free_port_0000, localhost};

    use crate::automap_core_functions::TestStatus;
    use crate::probe_researcher::{deploy_background_listener, generate_nonce};
    use std::net::SocketAddr;

    fn test_stream_acceptor_and_probe_8875_imitator(
        shutdown_delay_millis: u64,
        send_probe_socket: SocketAddr,
    ) {
        let message = u16_to_byte_array(8875);
        test_stream_acceptor_and_probe(&message, shutdown_delay_millis, send_probe_socket);
    }

    fn test_stream_acceptor_and_probe(
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

    fn u16_to_byte_array(x: u16) -> [u8; 2] {
        let b1: u8 = ((x >> 8) & 0xff) as u8;
        let b2: u8 = (x & 0xff) as u8;
        [b1, b2]
    }

    #[test]
    fn deploy_background_listener_with_good_probe_works() {
        let port = find_free_port_0000();
        let (handle, _) = deploy_background_listener(TestStatus::new(), port, 8875, 500);
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
        let port = find_free_port_0000();
        let (handle, _) = deploy_background_listener(TestStatus::new(), port, 8875, 500);
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
        let port = find_free_port_0000();
        let (handle, _) = deploy_background_listener(TestStatus::new(), port, 8875, 500);
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
        let port = find_free_port_0000();
        let (handle, _) = deploy_background_listener(TestStatus::new(), port, 8875, 500);
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
        let port = find_free_port_0000();
        let (handle, _) = deploy_background_listener(TestStatus::new(), port, 8875, 200);
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
        let port = find_free_port_0000();

        let (handle, status) = deploy_background_listener(TestStatus::new(), port, 1234, 10);

        assert_eq!(status.step_success, true);
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
