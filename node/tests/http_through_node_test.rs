// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use node_lib::test_utils::read_until_timeout;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str::FromStr;
use std::time::Duration;

// 'node' below must not be named '_' alone or disappear, or the MASQNode will be immediately reclaimed.
#[test]
fn http_through_node_integration() {
    let _node = utils::MASQNode::start_standard(
        "http_through_node_integration",
        None,
        true,
        true,
        false,
        true,
    );
    let mut stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:80").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();
    let request = "GET /index.html HTTP/1.1\r\nHost: www.testingmcafeesites.com\r\n\r\n".as_bytes();

    stream.write(request.clone()).unwrap();
    let buf = read_until_timeout(&mut stream);

    let response = String::from_utf8(buf).expect("Response is not UTF-8");
    assert_eq!(&response[9..15], &"200 OK"[..]);
    assert_eq!(
        response.contains("<title>URL for testing.</title>"),
        true,
        "{}",
        response
    );
}
