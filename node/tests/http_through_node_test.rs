// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate entry_dns_lib;
extern crate regex;
extern crate sub_lib;

mod utils;

use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str::FromStr;
use std::time::Duration;
use utils::read_until_timeout;

#[test]
#[allow(unused_variables)] // 'node' below must not become '_' or disappear, or the
                           // SubstratumNode will be immediately reclaimed.
fn http_through_node_integration() {
    let node = utils::SubstratumNode::start(None);
    let mut stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:80").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes();

    stream.write(request.clone()).unwrap();
    let buf = read_until_timeout(&mut stream);

    let response = String::from_utf8(buf).expect("Response is not UTF-8");
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
