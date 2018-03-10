// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;
extern crate sub_lib;
extern crate entry_dns_lib;

mod utils;

use std::net::TcpStream;
use std::net::SocketAddr;
use std::io::Write;
use std::io::Read;
use std::str::FromStr;
use sub_lib::test_utils::assert_matches;

#[test]
#[allow (unused_variables)] // 'node' below must not become '_' or disappear, or the
                            // SubstratumNode will be immediately reclaimed.
fn http_through_node_integration() {
    let request = "GET /html HTTP/1.1\r\nHost: httpbin.org\r\n\r\n".as_bytes ();
    let node = utils::SubstratumNode::start ();
    let mut stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:80").unwrap()).unwrap();

    stream.write(request.clone ()).unwrap ();
    let mut buf: [u8; 16384] = [0; 16384];
    let length = stream.read(&mut buf).unwrap ();

    let string_response = &String::from_utf8 (Vec::from (&buf[..length])).unwrap ()[..];

    assert_matches (string_response, "HTTP/1\\.1 200 OK");
    assert_matches (string_response, "Content-Type: text/html; charset=utf-8");
    assert_matches (string_response, "Content-Length: 3741");
    assert_matches (string_response, "Nevertheless, this old man's was a patient hammer wielded by a patient arm\\.");
    assert_matches (string_response, "It was the Bottle Conjuror!");
    assert_matches (string_response, "Oh, woe on woe!");
}
