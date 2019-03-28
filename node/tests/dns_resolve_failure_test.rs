// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

mod utils;

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::Duration;

#[test]
fn dns_resolve_failure_logs_warning_integration() {
    let mut node = utils::SubstratumNode::start(None);
    let mut stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:80").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let request = "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n".as_bytes();
    stream.write(request.clone()).unwrap();

    node.wait_for_log(
        "WARN: RoutingService: We have a situation! Unable to resolve DNS for stream key: ",
        Some(1000),
    );
}
