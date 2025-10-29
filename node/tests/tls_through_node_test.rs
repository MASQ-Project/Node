// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use native_tls::TlsConnector;
use native_tls::{HandshakeError, MidHandshakeTlsStream, TlsStream};
use node_lib::test_utils::*;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

#[test]
fn tls_through_node_integration() {
    let _node = utils::MASQNode::start_standard(
        "tls_through_node_integration",
        None,
        true,
        true,
        false,
        true,
    );

    let mut tls_stream = {
        let stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:443").unwrap())
            .expect("Could not connect to 127.0.0.1:443");
        stream
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .expect("Could not set read timeout to 1000ms");
        let connector = TlsConnector::new().expect("Could not build TlsConnector");
        match connector.connect(
            "www.example.com",
            stream.try_clone().expect("Couldn't clone TcpStream"),
        ) {
            Ok(s) => s,
            Err(HandshakeError::WouldBlock(interrupted_stream)) => {
                match handle_wouldblock(interrupted_stream) {
                    Ok(stream) => stream,
                    Err(e) => {
                        handle_connection_error(stream);
                        panic!("connection error after WouldBlock: {:?}", e);
                    }
                }
            }
            Err(e) => {
                handle_connection_error(stream);
                panic!("connection error: {:?}", e);
            }
        }
    };
    let request = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n".as_bytes();
    tls_stream
        .write(request.clone())
        .expect("Could not write request to TLS stream");
    let buf = read_until_timeout(&mut tls_stream);
    let _ = tls_stream.shutdown(); // Can't do anything about an error here

    let response = String::from_utf8(Vec::from(&buf[..])).expect("Response is not UTF-8");

    assert_eq!(&response[9..15], &"200 OK"[..]);
    assert_eq!(
        response.contains("<h1>Example Domain</h1>"),
        true,
        "{}",
        response
    );
}

fn handle_wouldblock(
    interrupted_stream: MidHandshakeTlsStream<TcpStream>,
) -> Result<TlsStream<TcpStream>, HandshakeError<TcpStream>> {
    let mut retries_left = 10;
    let mut retry_stream = interrupted_stream;
    while retries_left > 0 {
        retries_left -= 1;
        eprintln!(
            "Handshake interrupted, retrying... ({} retries left)",
            retries_left
        );
        thread::sleep(Duration::from_millis(100));
        match retry_stream.handshake() {
            Ok(stream) => return Ok(stream),
            Err(HandshakeError::WouldBlock(interrupted_stream)) => {
                retry_stream = interrupted_stream;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    panic!("Handshake never completed after retries");
}
