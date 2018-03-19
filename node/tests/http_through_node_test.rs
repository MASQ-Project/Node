// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;
extern crate sub_lib;
extern crate entry_dns_lib;

mod utils;

use std::net::TcpStream;
use std::net::SocketAddr;
use std::io::Write;
use std::io::Read;
use std::io::ErrorKind;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;
use sub_lib::utils::index_of;
use sub_lib::utils::to_string_s;

#[test]
#[allow (unused_variables)] // 'node' below must not become '_' or disappear, or the
                            // SubstratumNode will be immediately reclaimed.
fn chunked_http_through_node_integration() {
    let node = utils::SubstratumNode::start ();
    let mut stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:80").unwrap()).unwrap();
    let request = "GET /stream-bytes/30?seed=0&chunk_size=10 HTTP/1.1\r\nHost: httpbin.org\r\n\r\n".as_bytes ();
    let expected_response_chunks = vec! ( // these values are what seed=0 happens to give you
        vec! (97, 13, 10, 216, 194, 107, 66, 130, 103, 200, 77, 122, 149, 13, 10),
        vec! (97, 13, 10, 232, 129, 72, 193, 158, 64, 232, 251, 207, 230, 13, 10),
        vec! (97, 13, 10, 79, 186, 230, 175, 120, 25, 111, 156, 233, 247, 13, 10),
        vec! (48, 13, 10, 13, 10),
    );

    stream.write(request.clone ()).unwrap ();
    let mut buf: [u8; 16384] = [0; 16384];
    let mut begin_opt: Option<Instant> = None;
    let mut offset: usize = 0;
    stream.set_read_timeout (Some (Duration::from_millis (100))).unwrap ();
    loop {
        match stream.read (&mut buf[offset..]) {
            Err (e) => {
                if (e.kind () == ErrorKind::WouldBlock) || (e.kind () == ErrorKind::TimedOut) {
                    ()
                }
                else {
                    panic! ("Read error: {}", e);
                }
            },
            Ok (len) => {
                println! ("Integration test read {} bytes from Node", len);
                offset += len;
                begin_opt = Some (Instant::now ())
            }
        }
        match begin_opt {
            None => (),
            Some (begin) => {
                if Instant::now ().duration_since (begin).as_secs  () > 1 {break;}
            }
        }
    }

    let chunks_offset = index_of (&buf[..], b"\r\n\r\n").unwrap () + 4;
    let response = &buf[0..chunks_offset];
    assert_eq! (index_of (response, b"HTTP/1.1 200 OK\r\n"), Some (0), "{}", to_string_s (response));
    assert_eq! (index_of (response, b"Transfer-Encoding: chunked\r\n").is_some (), true, "{}", to_string_s (response));
    assert_eq! (index_of (response, b"Content-Length:").is_none (), true, "{}", to_string_s (response));
    let mut begin = chunks_offset;
    for index in 0..3 {
        let expected_response_chunk = &expected_response_chunks[index];
        let end = begin + expected_response_chunk.len ();
        assert_eq! (&buf[begin..end], &expected_response_chunk[..]);
        begin = end;
    }
}
