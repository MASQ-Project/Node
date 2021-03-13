// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::pmp::PmpTransactor;
use crate::probe_researcher::mock_tools::MockStream;
use crate::probe_researcher::{researcher_with_probe, FirstSectionData, Method};
use masq_lib::utils::find_free_port;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

//each of these tests requires the real server to be running

#[test]
#[ignore]
fn researcher_with_probe_works_server_integration() {
    let mut stdout = MockStream::new();
    let mut stderr = MockStream::new();
    let mut transferred_parameters = FirstSectionData {
        method: Method::Pmp,
        ip: IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap()),
        port: find_free_port(),
        transactor: Box::new(PmpTransactor::default()),
    };
    let server_address = SocketAddr::from_str("127.0.0.1:7005").unwrap();

    let result = researcher_with_probe(
        &mut stdout,
        &mut stderr,
        server_address,
        &mut transferred_parameters,
        5000,
    );

    thread::sleep(Duration::from_secs(2));
    assert_eq!(result, true);
    assert_eq!(stdout.stream, "Test of a port forwarded by using PMP protocol is starting. \
         \n\nHTTP/1.1 200 OK\r\nContent-Length: 67\r\n\r\nconnection: success; writing: success; connection shutdown: \
         success\n\nThe received nonce was evaluated to be a match; test passed"
    );
    assert!(stderr.stream.is_empty());
    assert_eq!(stdout.flush_count, 1);
    assert_eq!(stderr.flush_count, 1);
}

#[test]
#[ignore]
fn researcher_recives_a_message_about_failure_from_the_server_integration() {
    let mut stdout = MockStream::new();
    let mut stderr = MockStream::new();
    let mut transfered_parameters = FirstSectionData {
        method: Method::Pmp,
        ip: IpAddr::V4(Ipv4Addr::from_str("100.0.0.50").unwrap()),
        port: 3545,
        transactor: Box::new(PmpTransactor::default()),
    };
    let server_address = SocketAddr::from_str("127.0.0.1:7005").unwrap();

    let result = researcher_with_probe(
        &mut stdout,
        &mut stderr,
        server_address,
        &mut transfered_parameters,
        5000,
    );

    thread::sleep(Duration::from_secs(2));
    assert_eq!(result, false);
    assert_eq!(
        stdout.stream,
        "Test of a port forwarded by using PMP protocol is starting. \
     \n\nHTTP/1.1 408 Request Timeout\r\nContent-Length: 52\r\n\r\nConnection meant for the probe: \
      connection timed out\n\nThe probe detector detected no incoming probe"
    );
    assert!(stderr.stream.is_empty());
    assert_eq!(stdout.flush_count, 1);
    assert_eq!(stderr.flush_count, 1);
}
