// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate entry_dns_lib;
extern crate sub_lib;

use std::io;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;
use sub_lib::socket_server::SocketServer;
use sub_lib::main_tools::StdStreams;
use sub_lib::limiter::Limiter;
use entry_dns_lib::dns_socket_server::new_dns_socket_server;

#[test]
fn handles_two_consecutive_requests() {
    let port: u16 = 5454;
    let handle = thread::spawn (move || {
        let mut subject = new_dns_socket_server();
        subject.limiter = Limiter::with_only (2);
        let mut streams: StdStreams = StdStreams {
            stdin: &mut io::stdin (),
            stdout: &mut io::stdout (),
            stderr: &mut io::stderr ()
        };
        subject.initialize_as_root(&vec! (format! ("--dns_target"), format! ("1.2.3.4"),
            format! ("--dns_port"), format! ("{}", port)), &mut streams);
        subject.serve_without_root();
    });
    thread::sleep (Duration::from_millis (500));

    perform_transaction(port);
    perform_transaction(port);

    handle.join ().expect ("Couldn't join production thread");
}

fn perform_transaction(port: u16) {
    let request_bytes: Vec<u8> = vec![
        0x12, 0x34, // transaction ID
        0x81, 0x00, // is a query, opcode 0, recursion desired
        0x00, 0x01, // one query
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no answers, authorities, or additionals
        0x03, 0x77, 0x77, 0x77, // www
        0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E, // domain
        0x03, 0x63, 0x6F, 0x6D, 0x00, // com [end]
        0x00, 0x01, // type A (host address)
        0x00, 0x01  // class IN
    ];
    let socket = UdpSocket::bind(&format!("0.0.0.0:0")).expect("Couldn't bind socket");
    socket.connect (&format!("127.0.0.1:{}", port)).expect (&format! ("Couldn't connect to localhost:{}", port));
    let transmit_count = socket.send(request_bytes.as_slice()).expect("Couldn't send");
    assert_eq!(transmit_count, request_bytes.len());
    let mut response_bytes: [u8; 1024] = [0; 1024];
    socket.set_read_timeout (Some (Duration::from_secs (1))).unwrap ();
    let receive_count = socket.recv (&mut response_bytes).expect("Couldn't receive");
    let mut checker = ResponseChecker::new(&response_bytes);
    checker.check_bytes(&vec![0x12, 0x34]); // transaction ID
    checker.check_bytes(&vec![0x81, 0x80]); // flags
    checker.check_bytes(&vec![0x00, 0x01]); // one query
    checker.check_bytes(&vec![0x00, 0x01]); // one answer
    checker.check_bytes(&vec![0x00, 0x00, 0x00, 0x00]); // no authorities or additionals

    // query
    checker.check_bytes(&vec![0x03, 0x77, 0x77, 0x77]); // www
    checker.check_bytes(&vec![0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E]); // domain
    checker.check_bytes(&vec![0x03, 0x63, 0x6F, 0x6D, 0x00]); // com [end]
    checker.check_bytes(&vec![0x00, 0x01, 0x00, 0x01]); // type A, class IN

    // answer
    checker.check_bytes(&vec![0x03, 0x77, 0x77, 0x77]); // www
    checker.check_bytes(&vec![0x06, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E]); // domain
    checker.check_bytes(&vec![0x03, 0x63, 0x6F, 0x6D, 0x00]); // com [end]
    checker.check_bytes(&vec![0x00, 0x01, 0x00, 0x01]); // type A, class IN
    checker.check_bytes(&vec![0x00, 0x00, 0x0E, 0x10]); // time to live 3600
    checker.check_bytes(&vec![0x00, 0x04]); // 4 bytes of rdata
    checker.check_bytes(&vec![0x01, 0x02, 0x03, 0x04]);
    assert_eq!(checker.get_offset(), receive_count);
}

struct ResponseChecker<'a> {
    buf: &'a [u8],
    offset: usize
}

impl<'a> ResponseChecker<'a> {
    fn new(buf: &'a [u8]) -> ResponseChecker {
        ResponseChecker { buf, offset: 0 }
    }

    fn check_bytes(&mut self, expected_bytes: &Vec<u8>) {
        let actual_bytes = Vec::from(&self.buf[self.offset..(self.offset + expected_bytes.len())]);
        assert_eq!(ResponseChecker::make_hex_string(&actual_bytes), ResponseChecker::make_hex_string(expected_bytes),
                   "at offset {}", self.offset);
        self.offset += expected_bytes.len();
    }

    fn get_offset(&self) -> usize {
        self.offset
    }

    fn make_hex_string(bytes: &Vec<u8>) -> String {
        let strs: Vec<String> = bytes.iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        strs.join(" ")
    }
}
