// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;
extern crate sub_lib;
extern crate entry_dns_lib;
extern crate tls_api;
extern crate tls_api_native_tls;

mod utils;

use std::net::TcpStream;
use std::net::SocketAddr;
use std::io::Write;
use std::io::Read;
use std::io::ErrorKind;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;
use tls_api_native_tls::TlsConnector;
use tls_api::TlsConnector as TlsConnectorBase;
use tls_api::TlsConnectorBuilder as TlsConnectorBuilderBase;
use tls_api::TlsStream;
use std::thread;
use std::net::Shutdown;

const RETRIES_ALLOWED: usize = 10;

#[test]
#[allow (unused_variables)] // 'node' below must not become '_' or disappear, or the
// SubstratumNode will be immediately reclaimed.
fn tls_through_node_integration() {
    let node = utils::SubstratumNode::start();
    let (mut tls_stream, retries_remaining) = {
        let mut tls_stream: Option<TlsStream<TcpStream>> = None;
        let mut retries_remaining = RETRIES_ALLOWED;
        while retries_remaining > 0 {
            let stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:443").unwrap()).expect("Could not connect to 127.0.0.1:443");
            stream.set_read_timeout(Some(Duration::from_millis(100))).expect ("Could not set read timeout to 100ms");
            let connector = TlsConnector::builder().expect ("Could not construct TlsConnectorBuilder").build().expect ("Could not build TlsConnector");
            match connector.connect ("httpbin.org", stream.try_clone ().expect ("Couldn't clone TcpStream")) {
                Ok (s) => {tls_stream = Some (s); break},
                Err (e) => {
                    println!("Could not wrap TcpStream in TlsConnector - retrying: {:?}", e);
                    retries_remaining -= 1;
                    stream.shutdown(Shutdown::Both).unwrap();
                    thread::sleep(Duration::from_millis(5000));
                }
            }
        }
        (tls_stream.expect ("Couldn't handshake: retries expended"), retries_remaining)
    };
    let request = "GET /html HTTP/1.1\r\nHost: httpbin.org\r\n\r\n".as_bytes();
    tls_stream.write(request.clone()).expect ("Could not write request to TLS stream");

    let mut buf: [u8; 16384] = [0; 16384];
    let mut begin_opt: Option<Instant> = None;
    let mut offset: usize = 0;
    loop {
        match tls_stream.read(&mut buf[offset..]) {
            Err(e) => {
                if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) {
                    ()
                } else {
                    panic!("Read error: {}", e);
                }
            },
            Ok(len) => {
                offset += len;
                begin_opt = Some(Instant::now())
            }
        }
        match begin_opt {
            None => (),
            Some(begin) => {
                if Instant::now().duration_since(begin).as_secs() > 1 { break; }
            }
        }
    }
    tls_stream.shutdown().is_ok (); // Can't do anything about an error here

    let response = String::from_utf8(Vec::from(&buf[..])).expect ("Response is not UTF-8");
    assert_eq!(response.contains("200 OK"), true, "{}", response);
    assert_eq!(response.contains("It was the Bottle Conjuror!"), true, "{}", response);
    assert_eq!(response.contains("Oh, woe on woe! Oh, Death, why canst thou not sometimes be timely?"), true, "{}", response);

    println! ("Test succeeded after {} connection retries", RETRIES_ALLOWED - retries_remaining);
}


// TODO: Adjust this a little and then put it in utils.rs
pub fn read_until_pause_of (read: &mut Read, capacity: usize, seconds: u64) -> Vec<u8> {
    let mut buf = vec![0u8; capacity];
    let mut begin_opt: Option<Instant> = None;
    let mut offset: usize = 0;
    loop {
        match read.read (&mut buf[offset..]) {
            Err (e) => {
                if (e.kind () == ErrorKind::WouldBlock) || (e.kind () == ErrorKind::TimedOut) {
                    ()
                }
                    else {
                        panic! ("Read error: {}", e);
                    }
            },
            Ok (len) => {
                offset += len;
                begin_opt = Some (Instant::now ())
            }
        }
        match begin_opt {
            None => (),
            Some (begin) => {
                if Instant::now ().duration_since (begin).as_secs  () > seconds {break;}
            }
        }
    }
    buf
}
