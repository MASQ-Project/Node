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
    for index in 0..2 {
        let begin = chunks_offset + (index * 15);
        validate_chunk (&Vec::from (&buf[begin..(begin + 15)]));
    }
    let final_offset = chunks_offset + (3 * 15);
    assert_eq! (Vec::from (&buf[final_offset..(final_offset + 5)]), vec! ('0' as u8, 13, 10, 13, 10));
}

fn validate_chunk (chunk: &Vec<u8>) {
    assert_eq! (chunk.len (), 15, "Chunk should be 15 bytes long, not {}: {:?}", chunk.len (), chunk);
    assert_eq! (vec! ('A' as u8, 'a' as u8).contains (&chunk[0]), true, "First byte of chunk should be {} or {}, not {}: {:?}", 'A' as u8, 'a' as u8, chunk[0], chunk);
    check_crlf (chunk, 1);
    check_crlf (chunk, 13);
}

fn check_crlf (chunk: &Vec<u8>, offset: usize) {
    assert_eq! (chunk[offset], 13, "Byte at offset {} should be CR (13), not {}: {:?}", offset, chunk[offset], chunk);
    assert_eq! (chunk[offset + 1], 10, "Byte at offset {} should be LF (10), not {}: {:?}", offset + 1, chunk[offset + 1], chunk);
}
