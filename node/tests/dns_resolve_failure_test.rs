// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::utils::CommandConfig;
use node_lib::test_utils::{assert_string_contains, read_until_timeout};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::Duration;

#[test]
fn dns_resolve_failure_http_response_integration() {
    let _node_to_test_against = utils::MASQNode::start_standard(
        "dns_resolve_failure_http_response_integration",
        Some(CommandConfig::new().pair("--blockchain-service-url", "https://booga.com")),
        true,
        true,
        false,
        true,
    );
    let mut stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:80").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let request = "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n".as_bytes();
    stream.write(request.clone()).unwrap();

    let buf = read_until_timeout(&mut stream);
    let buf_str = String::from_utf8(buf).unwrap();
    assert_string_contains(&buf_str, "DNS Resolution Problem");
    assert_string_contains(&buf_str, "example.invalid");
}

#[test]
fn dns_resolve_failure_tls_response_integration() {
    let _node_to_test_against = utils::MASQNode::start_standard(
        "dns_resolve_failure_tls_response_integration",
        Some(CommandConfig::new().pair("--blockchain-service-url", "https://booga.com")),
        true,
        true,
        false,
        true,
    );
    let mut stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:443").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let client_hello = vec![
        0x16, // content_type: Handshake
        0x03, 0x03, // TLS 1.2
        0x00, 0x44, // length: 68
        0x01, // handshake_type: ClientHello
        0x00, 0x00, 0x40, // length: 64
        0x00, 0x00, // version: don't care
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // random: don't care
        0x00, // session_id_length
        0x00, 0x00, // cipher_suites_length
        0x00, // compression_methods_length
        0x00, 0x18, // extensions_length: 24
        0x00, 0x00, // extension_type: server_name
        0x00, 0x14, // extension_length: 20
        0x00, 0x12, // server_name_list_length: 18
        0x00, // server_name_type
        0x00, 0x0F, // server_name_length: 15
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'i', b'n', b'v', b'a', b'l', b'i',
        b'd', // server_name
    ];
    stream.write(&client_hello[..]).unwrap();

    let buf = read_until_timeout(&mut stream);
    assert_eq!(
        vec![
            0x15, // alert
            0x03, 0x03, // TLS 1.2
            0x00, 0x02, // packet length
            0x02, // fatal alert
            0x70, // unrecognized_name alert
        ],
        buf
    );
}
