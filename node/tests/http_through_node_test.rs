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

const CHUNK_DATA_LEN: usize = 10;
const CHUNK_COUNT: usize = 1;
const BUF_LEN: usize = 16384;

#[test]
#[allow (unused_variables)] // 'node' below must not become '_' or disappear, or the
                            // SubstratumNode will be immediately reclaimed.
fn chunked_http_through_node_integration() {
    let node = utils::SubstratumNode::start ();
    let mut stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:80").unwrap()).unwrap();
    let request_str = format! ("GET /stream-bytes/{}?seed=0&chunk_size={} HTTP/1.1\r\nHost: httpbin.org\r\n\r\n", CHUNK_COUNT * CHUNK_DATA_LEN, CHUNK_DATA_LEN);
    let request = request_str.as_bytes ();

    stream.write(request.clone ()).unwrap ();
    let mut buf: [u8; BUF_LEN] = [0; BUF_LEN];
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
    let chunk_size = chunk_size ();
    for index in 0..CHUNK_COUNT {
        let chunk_offset = chunks_offset + (index * chunk_size);
        let next_chunk_offset = chunk_offset + chunk_size;
        validate_chunk ( & Vec::from ( & buf[chunk_offset..next_chunk_offset]));
    }
    let final_chunk_offset = chunks_offset + (CHUNK_COUNT * chunk_size);
    let final_chunk_end = final_chunk_offset + 5;
    assert_eq! (Vec::from (&buf[final_chunk_offset..(final_chunk_end)]), vec! ('0' as u8, 13, 10, 13, 10));
}

fn validate_chunk (chunk: &Vec<u8>) {
    let chunk_size = chunk_size ();
    assert_eq! (chunk.len (), chunk_size, "Chunk should be {} bytes long, not {}: {:?}", chunk_size, chunk.len (), chunk);
    let uppercase_length = format! ("{:X}", CHUNK_DATA_LEN);
    let lowercase_length = format! ("{:x}", CHUNK_DATA_LEN);
    let length_possibilities = format! ("|{}|{}|", uppercase_length, lowercase_length);
    let length_length = uppercase_length.len ();
    let actual_length = format! ("{}", String::from_utf8_lossy(&chunk[0..length_length]));
    let delimited_actual_length = format! ("|{}|", actual_length);
    assert_eq! (length_possibilities.contains (&delimited_actual_length[..]), true, "First bytes of chunk should be {} or {}, not {}: {:?}", uppercase_length, lowercase_length, actual_length, chunk);
    check_crlf (chunk, chunk_size - 2 - CHUNK_DATA_LEN - 2);
    check_crlf (chunk, chunk_size - 2);
}

fn check_crlf (chunk: &Vec<u8>, offset: usize) {
    assert_eq! (chunk[offset], 13, "Byte at offset {} should be CR (13), not {}: {:?}", offset, chunk[offset], chunk);
    assert_eq! (chunk[offset + 1], 10, "Byte at offset {} should be LF (10), not {}: {:?}", offset + 1, chunk[offset + 1], chunk);
}

fn chunk_size () -> usize {
    hex_digit_count (CHUNK_DATA_LEN) + 2 + CHUNK_DATA_LEN + 2 // length field, CRLF, data, CRLF
}

fn hex_digit_count (n: usize) -> usize {
    let mut count = 0;
    let mut mut_n = n;
    while mut_n > 0 {
        mut_n >>= 4;
        count += 1;
    }
    count
}