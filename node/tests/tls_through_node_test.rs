// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate entry_dns_lib;
extern crate regex;
extern crate sub_lib;
extern crate tls_api;
extern crate tls_api_native_tls;

mod utils;

use std::io::Write;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use tls_api::HandshakeError;
use tls_api::TlsConnector as TlsConnectorBase;
use tls_api::TlsConnectorBuilder as TlsConnectorBuilderBase;
use tls_api::TlsStream;
use tls_api_native_tls::TlsConnector;
use utils::read_until_timeout;

#[test]
#[allow(unused_variables)] // 'node' below must not become '_' or disappear, or the
                           // SubstratumNode will be immediately reclaimed.
fn tls_through_node_integration() {
    let node = utils::SubstratumNode::start(None);
    let mut tls_stream = {
        let mut tls_stream: Option<TlsStream<TcpStream>> = None;
        let stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:443").unwrap())
            .expect("Could not connect to 127.0.0.1:443");
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("Could not set read timeout to 200ms");
        let connector = TlsConnector::builder()
            .expect("Could not construct TlsConnectorBuilder")
            .build()
            .expect("Could not build TlsConnector");
        match connector.connect(
            "example.com",
            stream.try_clone().expect("Couldn't clone TcpStream"),
        ) {
            Ok(s) => {
                tls_stream = Some(s);
            }
            Err(HandshakeError::Interrupted(interrupted_stream)) => {
                thread::sleep(Duration::from_millis(100));
                match interrupted_stream.handshake() {
                    Ok(stream) => tls_stream = Some(stream),
                    Err(e) => {
                        println!("connection error after interruption retry: {:?}", e);
                        handle_connection_error(stream);
                    }
                }
            }
            Err(e) => {
                println!("connection error: {:?}", e);
                handle_connection_error(stream);
            }
        }

        tls_stream.expect("Couldn't handshake")
    };
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes();
    tls_stream
        .write(request.clone())
        .expect("Could not write request to TLS stream");
    let buf = read_until_timeout(&mut tls_stream);
    tls_stream.shutdown().is_ok(); // Can't do anything about an error here

    let response = String::from_utf8(Vec::from(&buf[..])).expect("Response is not UTF-8");
    assert_eq!(&response[9..15], &"200 OK"[..]);
    assert_eq!(
        response.contains(
            "This domain is established to be used for illustrative examples in documents."
        ),
        true,
        "{}",
        response
    );
    assert_eq!(response.contains("You may use this\n    domain in examples without prior coordination or asking for permission."), true, "{}", response);
}

fn handle_connection_error(stream: TcpStream) {
    stream.shutdown(Shutdown::Both).is_ok();
    thread::sleep(Duration::from_millis(5000));
}
