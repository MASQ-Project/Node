// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate entry_dns_lib;
extern crate sub_lib;

mod utils;

use entry_dns_lib::packet_facade::PacketFacade;
use std::net::UdpSocket;
use std::time::Duration;

#[test]
fn handles_two_consecutive_dns_requests_integration() {
    let _node = utils::SubstratumNode::start(None);

    perform_transaction();
    perform_transaction();
}

fn perform_transaction() {
    let mut buf: [u8; 1024] = [0; 1024];
    let length = {
        let mut facade = PacketFacade::new(&mut buf, 12);
        facade.set_transaction_id(0x1234);
        facade.set_query(true);
        facade.set_opcode(0x0);
        facade.set_recursion_desired(true);
        facade.add_query("www.domain.com", 0x0001, 0x0001);
        facade.get_length()
    };

    let socket = UdpSocket::bind(&format!("0.0.0.0:0")).expect("Couldn't bind socket");
    socket
        .connect(&format!("127.0.0.1:53"))
        .expect("Couldn't connect");
    let transmit_count = socket.send(&buf[..length]).expect("Couldn't send");
    assert_eq!(transmit_count, length);
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("Couldn't set read timeout");
    let receive_count = socket.recv(&mut buf).expect("Couldn't receive");

    {
        let facade = PacketFacade::new(&mut buf, receive_count);
        assert_eq!(facade.get_transaction_id(), Some(0x1234));
        assert_eq!(facade.is_query(), Some(false));
        assert_eq!(facade.is_truncated(), Some(false));
        assert_eq!(facade.is_authoritative_answer(), Some(false));
        assert_eq!(facade.is_recursion_desired(), Some(true));
        assert_eq!(facade.is_recursion_available(), Some(true));
        assert_eq!(facade.get_opcode(), Some(0x0));
        assert_eq!(facade.get_rcode(), Some(0x0));
        let queries = facade.get_queries().unwrap();
        assert_eq!(queries[0].get_query_name(), "www.domain.com");
        assert_eq!(queries[0].get_query_type(), 0x0001);
        assert_eq!(queries[0].get_query_class(), 0x0001);
        assert_eq!(queries.len(), 1);
        let answers = facade.get_answers().unwrap();
        assert_eq!(answers[0].get_name(), "www.domain.com");
        assert_eq!(answers[0].get_time_to_live(), 3600);
        assert_eq!(answers[0].get_resource_type(), 0x0001);
        assert_eq!(answers[0].get_resource_class(), 0x0001);
        assert_eq!(make_hex_string(answers[0].get_rdata()), "7F 00 00 01");
        assert_eq!(answers.len(), 1);
    }
}

fn make_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join(" ")
}
